<?php
/**
 * Authorization Code flow service.
 *
 * @package GalatanOvidiu\Charter
 */

declare(strict_types=1);

namespace GalatanOvidiu\Charter\OAuth;

use GalatanOvidiu\Charter\Security\AuditLog;
use GalatanOvidiu\Charter\Security\RateLimiter;
use GalatanOvidiu\Charter\Security\SourceAddress;
use GalatanOvidiu\Charter\Site\SiteState;

/**
 * Validates authorization requests and executes explicit user consent.
 *
 * @since 0.1.0
 */
final class AuthorizationService {

	public const GENERAL_SCOPE        = AccessPolicy::GENERAL_SCOPE;
	public const OFFLINE_ACCESS_SCOPE = 'offline_access';

	/**
	 * Creates the authorization service.
	 *
	 * @since 0.1.0
	 *
	 * @param SiteState              $siteState   Site lifecycle and identity.
	 * @param ClientRegistry         $clients     Pre-registered clients.
	 * @param CredentialStore        $credentials Credential persistence.
	 * @param ClientMetadataResolver $clientMetadata Authorization-time client onboarding.
	 * @param RateLimiter            $rateLimiter OAuth abuse counters.
	 * @param AuditLog               $audit Security event ledger.
	 * @param AccessPolicyProvider   $accessPolicy Active exact resource and scope registrations.
	 * @param EmergencyContainment   $containment Issuer-local emergency mode.
	 * @param SigningKeyLifecycle    $signingKeys Issuer-local credential-key lifecycle.
	 */
	public function __construct(
		private readonly SiteState $siteState,
		private readonly ClientRegistry $clients,
		private readonly CredentialStore $credentials,
		private readonly ClientMetadataResolver $clientMetadata,
		private readonly RateLimiter $rateLimiter,
		private readonly AuditLog $audit,
		private readonly AccessPolicyProvider $accessPolicy,
		private readonly EmergencyContainment $containment,
		private readonly SigningKeyLifecycle $signingKeys
	) {
	}

	/**
	 * Validates an authorization request without creating state.
	 *
	 * @since 0.1.0
	 *
	 * @param array<string, mixed> $parameters Request parameters.
	 * @throws ProtocolException When the request is invalid or the issuer is unavailable.
	 */
	public function validate( array $parameters ): AuthorizationRequest {
		$validated = $this->validateLocalParameters( $parameters );
		$this->consumeAuthorizationLimit(
			$validated['rate_policy'],
			$validated['issuer'],
			'authorization_issuer',
			'issuer',
			$validated['client_id'],
			null,
			$validated['timestamp']
		);
		try {
			$client = $this->clientMetadata->resolveForAuthorization( $validated['issuer'], $validated['client_id'], time() );
		} catch ( ClientMetadataResolutionException ) {
			throw new ProtocolException( 'temporarily_unavailable', 'The client metadata could not be validated.', 503 );
		}

		if ( null === $client || ! $client->allowsRedirectUri( $validated['redirect_uri'] ) ) {
			throw new ProtocolException( 'invalid_request', 'The client or redirect URI is invalid.' );
		}

		$continuingAccess = $validated['offline_access']
			|| $client->supportsGrantType( Client::GRANT_REFRESH_TOKEN );

		return new AuthorizationRequest(
			$validated['issuer'],
			$validated['resource'],
			$client,
			$validated['redirect_uri'],
			$validated['scope'],
			$validated['challenge'],
			$validated['state'],
			$continuingAccess,
			$validated['policy']->consentScopes( $validated['scope'] )
		);
	}

	/**
	 * Validates issuer state and request syntax without resolving client metadata.
	 *
	 * This is the complete logged-out boundary: successful preflight may continue
	 * to WordPress authentication, while client discovery waits until a user is
	 * authenticated.
	 *
	 * @param array<string, mixed> $parameters Request parameters.
	 * @throws ProtocolException When the request is invalid or the issuer is unavailable.
	 */
	public function preflight( array $parameters ): void {
		$this->validateLocalParameters( $parameters );
	}

	/**
	 * Validates every request fact that does not require remote client metadata.
	 *
	 * @param array<string, mixed> $parameters Request parameters.
	 * @return array{issuer:string,client_id:string,redirect_uri:string,state:?string,resource:string,scope:string,challenge:string,offline_access:bool,policy:AccessPolicy,rate_policy:array<mixed,mixed>,timestamp:int}
	 * @throws ProtocolException When the request is invalid or the issuer is unavailable.
	 */
	private function validateLocalParameters( array $parameters ): array {
		// phpcs:disable WordPress.Security.EscapeOutput.ExceptionNotEscaped -- Exact prevalidated redirect and state values are protocol data; escaping would corrupt their OAuth bindings.
		$identity = $this->siteState->identity();
		if ( ! $this->siteState->isEnabled() || ! $this->siteState->requestMatchesIdentity() || null === $identity ) {
			throw new ProtocolException( 'temporarily_unavailable', 'The OAuth issuer is not enabled.', 503 );
		}
		if ( ! $this->containment->issuanceAllowed() || ! $this->signingKeys->credentialOperationsAllowed() ) {
			throw new ProtocolException( 'temporarily_unavailable', 'OAuth credential issuance is temporarily unavailable.', 503 );
		}

		$issuer        = $identity->issuer();
		$clientId      = self::requiredParameter( $parameters, 'client_id', 2048 );
		$redirectUri   = self::requiredParameter( $parameters, 'redirect_uri', 2048 );
		$state         = self::optionalParameter( $parameters, 'state', 2048 );
		$errorRedirect = $this->trustedErrorRedirect( $issuer, $clientId, $redirectUri );
		$localClient   = $this->clients->findActive( $issuer, $clientId );
		if ( null !== $localClient && ClientRegistry::SOURCE_CIMD !== $localClient->source() && ! $localClient->allowsRedirectUri( $redirectUri ) ) {
			throw new ProtocolException( 'invalid_request', 'The client or redirect URI is invalid.' );
		}
		$timestamp  = time();
		$ratePolicy = $this->enforceAuthorizationLimit( $issuer, $clientId, null, $timestamp );

		if ( 'code' !== self::requiredParameter( $parameters, 'response_type', 32 ) ) {
			throw new ProtocolException( 'unsupported_response_type', 'Only the code response type is supported.', 400, $errorRedirect, $state );
		}
		if ( 'S256' !== self::requiredParameter( $parameters, 'code_challenge_method', 16 ) ) {
			throw new ProtocolException( 'invalid_request', 'PKCE with S256 is required.', 400, $errorRedirect, $state );
		}

		$challenge = self::requiredParameter( $parameters, 'code_challenge', 128 );
		if ( 1 !== preg_match( '/^[A-Za-z0-9_-]{43}$/D', $challenge ) ) {
			throw new ProtocolException( 'invalid_request', 'The PKCE code challenge is invalid.', 400, $errorRedirect, $state );
		}

		$resource = array_key_exists( 'resource', $parameters )
			? self::requiredParameter( $parameters, 'resource', 2048 )
			: $issuer;
		$policy   = $this->accessPolicy->forIssuer( $issuer );
		if ( ! $policy->hasResource( $resource ) ) {
			throw new ProtocolException( 'invalid_target', 'The requested protected resource is invalid.', 400, $errorRedirect, $state );
		}

		$scopeInput  = array_key_exists( 'scope', $parameters )
			? self::requiredParameter( $parameters, 'scope', 1024 )
			: ( in_array( self::GENERAL_SCOPE, $policy->scopesForResource( $resource ), true ) ? self::GENERAL_SCOPE : '' );
		$scopeTokens = preg_split( '/ +/', trim( $scopeInput ) );
		if ( '' === $scopeInput || ! is_array( $scopeTokens ) || array() === $scopeTokens || in_array( '', $scopeTokens, true ) ) {
			throw new ProtocolException( 'invalid_scope', 'The requested scope is invalid.', 400, $errorRedirect, $state );
		}
		$scopeTokens     = array_values( array_unique( $scopeTokens ) );
		$offlineAccess   = in_array( self::OFFLINE_ACCESS_SCOPE, $scopeTokens, true );
		$delegatedScopes = array_values( array_diff( $scopeTokens, array( self::OFFLINE_ACCESS_SCOPE ) ) );
		$canonicalScope  = $policy->canonicalScope( $resource, $delegatedScopes );
		if ( null === $canonicalScope ) {
			throw new ProtocolException( 'invalid_scope', 'The requested scope is invalid.', 400, $errorRedirect, $state );
		}
		// phpcs:enable WordPress.Security.EscapeOutput.ExceptionNotEscaped

		return array(
			'issuer'         => $issuer,
			'client_id'      => $clientId,
			'redirect_uri'   => $redirectUri,
			'state'          => $state,
			'resource'       => $resource,
			'scope'          => $canonicalScope,
			'challenge'      => $challenge,
			'offline_access' => $offlineAccess,
			'policy'         => $policy,
			'rate_policy'    => $ratePolicy,
			'timestamp'      => $timestamp,
		);
	}

	/**
	 * Returns a local redirect authority only for established trusted clients.
	 *
	 * @param string $issuer Exact issuer.
	 * @param string $clientId Exact client identifier.
	 * @param string $redirectUri Submitted redirect URI.
	 */
	private function trustedErrorRedirect( string $issuer, string $clientId, string $redirectUri ): ?string {
		$registration = $this->clients->findRegistration( $issuer, $clientId );
		if (
			null === $registration
			|| ClientRegistry::STATUS_ACTIVE !== $registration->status()
			|| ( ClientRegistry::SOURCE_PRE_REGISTERED !== $registration->source() && null === $registration->authorizedAt() )
		) {
			return null;
		}
		$client = $this->clients->findActive( $issuer, $clientId );

		return null !== $client && $client->allowsRedirectUri( $redirectUri ) ? $redirectUri : null;
	}

	/**
	 * Starts a single-use ten-minute consent transaction.
	 *
	 * @since 0.1.0
	 *
	 * @param array<string, mixed> $parameters Request parameters.
	 * @param int                  $userId     Authorizing WordPress user.
	 * @return array{transaction: string, request: AuthorizationRequest, reusable_grant_id: int|null} Consent data.
	 * @throws ProtocolException When the request cannot start.
	 */
	public function begin( array $parameters, int $userId ): array {
		if ( $userId <= 0 || ! UserEligibility::isActiveForCurrentSite( $userId ) ) {
			throw new ProtocolException( 'access_denied', 'A current WordPress user is required.', 403 );
		}
		$identity = $this->siteState->identity();
		if ( null === $identity ) {
			throw new ProtocolException( 'temporarily_unavailable', 'The OAuth issuer is not enabled.', 503 );
		}
		if ( ! $this->signingKeys->credentialOperationsAllowed() ) {
			throw new ProtocolException( 'temporarily_unavailable', 'OAuth credential issuance is temporarily unavailable.', 503 );
		}
		$this->enforceAuthorizationLimit( $identity->issuer(), self::requiredParameter( $parameters, 'client_id', 2048 ), $userId, time() );

		$request     = $this->validate( $parameters );
		$transaction = $this->credentials->issueAuthorizationRequest( $request, $userId, time() );
		$grant       = $this->requiresVisibleConsent( $request ) ? null : $this->credentials->findReusableGrant( $request, $userId, time() );

		return array(
			'transaction'       => $transaction,
			'request'           => $request,
			'reusable_grant_id' => null === $grant ? null : $grant->id(),
		);
	}

	/**
	 * Reports whether native public-client impersonation requires a fresh prompt.
	 *
	 * @param AuthorizationRequest $request Validated authorization request.
	 */
	private function requiresVisibleConsent( AuthorizationRequest $request ): bool {
		return Client::AUTH_NONE === $request->client()->authenticationMethod()
			&& RedirectUriValidator::isLoopback( $request->redirectUri() );
	}

	/**
	 * Completes one exact consent transaction and returns the client redirect.
	 *
	 * @since 0.1.0
	 *
	 * @param string   $transaction Presented transaction credential.
	 * @param int      $userId      Current WordPress user.
	 * @param bool     $approved       Whether the user approved access.
	 * @param int|null $reusableGrantId Exact active grant approved previously.
	 * @throws ProtocolException When the transaction is invalid or already used.
	 */
	public function complete( string $transaction, int $userId, bool $approved, ?int $reusableGrantId = null ): string {
		$identity = $this->siteState->identity();
		if ( ! $this->siteState->isEnabled() || ! $this->siteState->requestMatchesIdentity() || null === $identity ) {
			throw new ProtocolException( 'temporarily_unavailable', 'The OAuth issuer is not enabled.', 503 );
		}
		if ( ! $this->signingKeys->credentialOperationsAllowed() ) {
			throw new ProtocolException( 'temporarily_unavailable', 'OAuth credential issuance is temporarily unavailable.', 503 );
		}

		$timestamp = time();
		$record    = $this->credentials->find( CredentialStore::AUTHORIZATION_REQUEST, $identity->issuer(), $transaction );
		$policy    = $this->accessPolicy->forIssuer( $identity->issuer() );
		if (
			null === $record
			|| ! $record->isActiveAt( $timestamp )
			|| $record->issuer() !== $identity->issuer()
			|| ! $policy->bindingAvailable( $record->resource(), $record->scope() )
			|| $record->userId() !== $userId
			|| ! UserEligibility::isActiveForCurrentSite( $userId )
		) {
			throw new ProtocolException( 'invalid_request', 'The authorization transaction is invalid or expired.' );
		}

		$client = $this->clients->findActive( $record->issuer(), $record->clientId() );
		if ( null === $client || ( ClientRegistry::SOURCE_CIMD !== $client->source() && ! $client->allowsRedirectUri( $record->redirectUri() ) ) ) {
			throw new ProtocolException( 'invalid_request', 'The authorization transaction is invalid or expired.' );
		}
		if ( $approved && ! $this->containment->issuanceAllowed() ) {
			throw new ProtocolException( 'temporarily_unavailable', 'OAuth credential issuance is temporarily unavailable.', 503, $record->redirectUri(), $record->requestState() ); // phpcs:ignore WordPress.Security.EscapeOutput.ExceptionNotEscaped -- Stored exact redirect and state values are protocol bindings.
		}

		if ( ! $approved ) {
			if ( ! $this->credentials->consume( $record, $timestamp ) ) {
				throw new ProtocolException( 'invalid_request', 'The authorization transaction is invalid or expired.' );
			}

			return self::redirectWithParameters(
				$record->redirectUri(),
				array(
					'error' => 'access_denied',
					'state' => $record->requestState(),
					'iss'   => $record->issuer(),
				)
			);
		}

		if ( ! $this->clients->markAuthorized( $record->issuer(), $record->clientId(), $timestamp ) ) {
			throw new ProtocolException( 'temporarily_unavailable', 'The client authorization state could not be recorded.', 503 );
		}

		$code = $this->credentials->approveAuthorization( $record, $timestamp, $reusableGrantId );
		if ( null === $code ) {
			throw new ProtocolException( 'invalid_request', 'The authorization transaction is invalid or expired.' );
		}

		return self::redirectWithParameters(
			$record->redirectUri(),
			array(
				'code'  => $code,
				'state' => $record->requestState(),
				'iss'   => $record->issuer(),
			)
		);
	}

	/**
	 * Appends an authorization response without changing an existing query.
	 *
	 * @since 0.1.0
	 *
	 * @param string                     $redirectUri Exact validated redirect URI.
	 * @param array<string, string|null> $parameters Response parameters.
	 */
	public static function redirectWithParameters( string $redirectUri, array $parameters ): string {
		$encoded = array();
		foreach ( array_filter( $parameters, 'is_string' ) as $name => $value ) {
			$encoded[] = rawurlencode( $name ) . '=' . rawurlencode( $value );
		}

		return $redirectUri . ( str_contains( $redirectUri, '?' ) ? '&' : '?' ) . implode( '&', $encoded );
	}

	/**
	 * Reads one required bounded scalar parameter.
	 *
	 * @since 0.1.0
	 *
	 * @param array<string, mixed> $parameters Request parameters.
	 * @param string               $name       Parameter name.
	 * @param int                  $maxLength  Maximum byte length.
	 * @throws ProtocolException When the value is absent, empty, or invalid.
	 */
	private static function requiredParameter( array $parameters, string $name, int $maxLength ): string {
		$value = $parameters[ $name ] ?? null;
		if ( ! is_string( $value ) || '' === $value || strlen( $value ) > $maxLength ) {
			throw new ProtocolException( 'invalid_request', 'A required authorization parameter is invalid.' );
		}

		return $value;
	}

	/**
	 * Reads one optional bounded scalar parameter.
	 *
	 * @since 0.1.0
	 *
	 * @param array<string, mixed> $parameters Request parameters.
	 * @param string               $name       Parameter name.
	 * @param int                  $maxLength  Maximum byte length.
	 * @throws ProtocolException When the value is present but invalid.
	 */
	private static function optionalParameter( array $parameters, string $name, int $maxLength ): ?string {
		if ( ! array_key_exists( $name, $parameters ) ) {
			return null;
		}

		$value = $parameters[ $name ];
		if ( ! is_string( $value ) || strlen( $value ) > $maxLength ) {
			throw new ProtocolException( 'invalid_request', 'An authorization parameter is invalid.' );
		}

		return $value;
	}

	/**
	 * Applies the accepted client/network and represented-user authorization limits.
	 *
	 * @param string   $issuer Exact issuer.
	 * @param string   $clientId Exact client identifier.
	 * @param int|null $userId Represented user, or null before authentication.
	 * @param int      $timestamp Current timestamp.
	 * @return array<mixed, mixed> Complete validated rate-limit policy.
	 * @throws ProtocolException When the request is limited or policy is unavailable.
	 */
	private function enforceAuthorizationLimit( string $issuer, string $clientId, ?int $userId, int $timestamp ): array {
		$defaults = array(
			'authorization_issuer'         => 600,
			'authorization_network'        => 120,
			'authorization_network_client' => 60,
			'authorization_user_client'    => 20,
		);
		$policy   = apply_filters( 'charter_oauth_rate_limit_policy', $defaults, $issuer ); // phpcs:ignore WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedHooknameFound -- One accepted advanced OAuth policy hook.
		if ( ! is_array( $policy ) ) {
			throw new ProtocolException( 'temporarily_unavailable', 'The authorization policy is unavailable.', 503 );
		}

		$buckets = null === $userId
			? array(
				'authorization_network'        => SourceAddress::current(),
				'authorization_network_client' => SourceAddress::current() . "\0" . $clientId,
			)
			: array( 'authorization_user_client' => (string) $userId . "\0" . $clientId );
		foreach ( $buckets as $surface => $subject ) {
			$this->consumeAuthorizationLimit( $policy, $issuer, $surface, $subject, $clientId, $userId, $timestamp );
		}

		return $policy;
	}

	/**
	 * Consumes one validated authorization budget.
	 *
	 * @param array<mixed, mixed> $policy Complete operator policy.
	 * @param string              $issuer Exact issuer.
	 * @param string              $surface Stable counter surface.
	 * @param string              $subject Non-secret counter subject.
	 * @param string              $clientId Exact client identifier.
	 * @param int|null            $userId Represented user, or null before authentication.
	 * @param int                 $timestamp Current timestamp.
	 * @throws ProtocolException When the request is limited or policy is unavailable.
	 */
	private function consumeAuthorizationLimit( array $policy, string $issuer, string $surface, string $subject, string $clientId, ?int $userId, int $timestamp ): void {
		$limit = $policy[ $surface ] ?? null;
		if ( ! is_int( $limit ) || 1 > $limit ) {
			throw new ProtocolException( 'temporarily_unavailable', 'The authorization policy is unavailable.', 503 );
		}
		$decision = $this->rateLimiter->consume( $issuer, $surface, $subject, $limit, 10 * MINUTE_IN_SECONDS, $timestamp );
		if ( $decision->allowed() ) {
			return;
		}
		if ( $decision->count() === $decision->limit() + 1 ) {
			$this->audit->record( $issuer, 'rate_limit_escalated', 'blocked', $surface, null, $userId, $clientId, SourceAddress::current(), $timestamp );
		}

		throw new ProtocolException( 'temporarily_unavailable', 'Too many authorization requests.', 429, null, null, $decision->retryAfter() ); // phpcs:ignore WordPress.Security.EscapeOutput.ExceptionNotEscaped -- Internal decision state, not output.
	}
}
