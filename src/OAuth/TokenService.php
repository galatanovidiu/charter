<?php
/**
 * OAuth token exchange, refresh, and validation.
 *
 * @package GalatanOvidiu\Charter
 */

declare(strict_types=1);

namespace GalatanOvidiu\Charter\OAuth;

use GalatanOvidiu\Charter\Security\AuditLog;
use GalatanOvidiu\Charter\Security\RateLimitDecision;
use GalatanOvidiu\Charter\Security\RateLimiter;
use GalatanOvidiu\Charter\Security\SourceAddress;
use GalatanOvidiu\Charter\Site\SiteState;

/**
 * Executes exact client-bound token lifecycle operations.
 *
 * @since 0.1.0
 */
final class TokenService {
	private const DEFAULT_RATE_POLICY = array(
		'token_network'             => 600,
		'token_network_client'      => 300,
		'token_failures_network'    => 20,
		'revocation_network'        => 120,
		'revocation_network_client' => 60,
	);

	private const REVOCABLE_TOKEN_TYPES = array(
		CredentialStore::ACCESS_TOKEN,
		CredentialStore::REFRESH_TOKEN,
	);

	/**
	 * Atomic issuer-local abuse counters.
	 *
	 * @var RateLimiter
	 */
	private readonly RateLimiter $rateLimiter;

	/**
	 * Secret-free security event ledger.
	 *
	 * @var AuditLog
	 */
	private readonly AuditLog $audit;

	/**
	 * Creates the token service.
	 *
	 * @since 0.1.0
	 *
	 * @param SiteState            $siteState Site lifecycle and identity.
	 * @param ClientRegistry       $clients Client registry.
	 * @param CredentialStore      $credentials Grant and credential persistence.
	 * @param AccessPolicyProvider $accessPolicy Active exact resource and scope registrations.
	 * @param EmergencyContainment $containment Issuer-local emergency mode.
	 * @param SigningKeyLifecycle  $signingKeys Issuer-local credential-key lifecycle.
	 * @param RateLimiter|null     $rateLimiter Optional shared abuse counter.
	 * @param AuditLog|null        $audit Optional shared security ledger.
	 */
	public function __construct(
		private readonly SiteState $siteState,
		private readonly ClientRegistry $clients,
		private readonly CredentialStore $credentials,
		private readonly AccessPolicyProvider $accessPolicy,
		private readonly EmergencyContainment $containment,
		private readonly SigningKeyLifecycle $signingKeys,
		?RateLimiter $rateLimiter = null,
		?AuditLog $audit = null
	) {
		$this->rateLimiter = $rateLimiter ?? new RateLimiter();
		$this->audit       = $audit ?? new AuditLog();
	}

	/**
	 * Executes an authorization-code exchange or refresh rotation.
	 *
	 * @since 0.1.0
	 *
	 * @param array<mixed> $parameters Form request parameters.
	 * @return array{access_token: string, token_type: string, expires_in: int, scope: string, resource: string, refresh_token?: string} Token response.
	 * @throws ProtocolException When request validation fails.
	 */
	public function exchange( array $parameters ): array {
		$identity = $this->siteState->identity();
		if ( ! $this->siteState->isEnabled() || ! $this->siteState->requestMatchesIdentity() || null === $identity ) {
			throw new ProtocolException( 'temporarily_unavailable', 'The OAuth issuer is not enabled.', 503 );
		}

		$grantType = self::requiredParameter( $parameters, 'grant_type', 64 );
		$clientId  = self::requiredParameter( $parameters, 'client_id', 2048 );
		$source    = SourceAddress::current();
		$timestamp = time();
		$policy    = $this->rateLimitPolicy( $identity->issuer() );
		$this->enforceFailureBackoff( $identity->issuer(), 'token_failures_network', $source, $policy, $clientId, $timestamp );
		$this->enforceRateLimit( $identity->issuer(), 'token_network', $source, $policy, $clientId, $timestamp );
		$this->enforceRateLimit( $identity->issuer(), 'token_network_client', $source . "\0" . $clientId, $policy, $clientId, $timestamp );
		$secretPresented = array_key_exists( 'client_secret', $parameters );
		$clientSecret    = null;
		if ( $secretPresented ) {
			$presentedValue = $parameters['client_secret'] ?? null;
			if ( ! is_string( $presentedValue ) ) {
				throw new ProtocolException( 'invalid_client', 'Client authentication failed.', 401 );
			}
			$clientSecret = $presentedValue;
		}

		$client = $this->clients->authenticateForTokenEndpoint( $identity->issuer(), $clientId, $secretPresented, $clientSecret );
		if ( null === $client ) {
			throw new ProtocolException( 'invalid_client', 'Client authentication failed.', 401 );
		}
		if (
			in_array( $grantType, array( Client::GRANT_AUTHORIZATION_CODE, Client::GRANT_REFRESH_TOKEN ), true )
			&& ( ! $this->containment->issuanceAllowed() || ! $this->signingKeys->credentialOperationsAllowed() )
		) {
			throw new ProtocolException( 'temporarily_unavailable', 'OAuth credential issuance is temporarily unavailable.', 503 );
		}

		$response = match ( $grantType ) {
			Client::GRANT_AUTHORIZATION_CODE => $this->exchangeAuthorizationCode( $parameters, $client ),
			Client::GRANT_REFRESH_TOKEN => $this->exchangeRefreshToken( $parameters, $client ),
			default => throw new ProtocolException( 'unsupported_grant_type', 'The requested grant type is not supported.' ),
		};
		$this->rateLimiter->relieve( $identity->issuer(), 'token_failures_network', $source );

		return $response;
	}

	/**
	 * Revokes the complete grant identified by an owned access or refresh token.
	 *
	 * Unknown, retired, and cross-client tokens deliberately produce the same
	 * successful result so the endpoint cannot be used as a token oracle.
	 *
	 * @since 0.1.0
	 *
	 * @param array<mixed> $parameters Form request parameters.
	 * @throws ProtocolException When issuer, request, or client validation fails.
	 */
	public function revoke( array $parameters ): void {
		$identity = $this->siteState->identity();
		if ( ! $this->siteState->isEnabled() || ! $this->siteState->requestMatchesIdentity() || null === $identity ) {
			throw new ProtocolException( 'temporarily_unavailable', 'The OAuth issuer is not enabled.', 503 );
		}

		$clientId  = self::requiredParameter( $parameters, 'client_id', 2048 );
		$source    = SourceAddress::current();
		$timestamp = time();
		$policy    = $this->rateLimitPolicy( $identity->issuer() );
		$this->enforceRateLimit( $identity->issuer(), 'revocation_network', $source, $policy, $clientId, $timestamp );
		$this->enforceRateLimit( $identity->issuer(), 'revocation_network_client', $source . "\0" . $clientId, $policy, $clientId, $timestamp );
		$secretPresented = array_key_exists( 'client_secret', $parameters );
		$clientSecret    = null;
		if ( $secretPresented ) {
			$presentedValue = $parameters['client_secret'] ?? null;
			if ( ! is_string( $presentedValue ) ) {
				throw new ProtocolException( 'invalid_client', 'Client authentication failed.', 401 );
			}
			$clientSecret = $presentedValue;
		}

		$client = $this->clients->authenticateForTokenEndpoint( $identity->issuer(), $clientId, $secretPresented, $clientSecret );
		if ( null === $client ) {
			throw new ProtocolException( 'invalid_client', 'Client authentication failed.', 401 );
		}

		$presented = self::requiredParameter( $parameters, 'token', 256 );
		$types     = self::REVOCABLE_TOKEN_TYPES;
		$hint      = $parameters['token_type_hint'] ?? null;
		if ( null !== $hint && ( ! is_string( $hint ) || strlen( $hint ) > 64 ) ) {
			throw new ProtocolException( 'invalid_request', 'The token type hint is invalid.' );
		}
		if ( is_string( $hint ) && in_array( $hint, self::REVOCABLE_TOKEN_TYPES, true ) ) {
			$types = array_values( array_unique( array_merge( array( $hint ), $types ) ) );
		}
		if ( ! $this->signingKeys->credentialOperationsAllowed() ) {
			return;
		}

		foreach ( $types as $type ) {
			$record = $this->credentials->find( $type, $identity->issuer(), $presented );
			if ( null === $record ) {
				continue;
			}

			$grantId = $record->grantId();
			$grant   = is_int( $grantId ) ? $this->credentials->findGrant( $grantId ) : null;
			if (
				null !== $grant
				&& $record->issuer() === $identity->issuer()
				&& $record->clientId() === $client->clientId()
				&& $grant->issuer() === $record->issuer()
				&& $grant->clientId() === $record->clientId()
				&& $grant->resource() === $record->resource()
				&& $grant->userId() === $record->userId()
				&& $grant->scope() === $record->scope()
			) {
				$timestamp = time();
				if ( $this->credentials->revokeGrant( $grant->id(), $timestamp, 'rfc7009_revocation' ) ) {
					$this->clients->markActivity( $record->issuer(), $record->clientId(), $timestamp );
				}
			}

			return;
		}
	}

	/**
	 * Exchanges one authorization code using mandatory S256 PKCE.
	 *
	 * @param array<mixed> $parameters Form parameters.
	 * @param Client       $client Authenticated exact client.
	 * @return array{access_token: string, token_type: string, expires_in: int, scope: string, resource: string, refresh_token?: string}
	 * @throws ProtocolException When exchange validation fails.
	 */
	private function exchangeAuthorizationCode( array $parameters, Client $client ): array {
		if ( ! $client->supportsGrantType( Client::GRANT_AUTHORIZATION_CODE ) ) {
			throw new ProtocolException( 'unauthorized_client', 'The client cannot use this grant type.' );
		}

		$identity = $this->siteState->identity();
		if ( null === $identity ) {
			throw new ProtocolException( 'temporarily_unavailable', 'The OAuth issuer is not enabled.', 503 );
		}

		$code     = self::requiredParameter( $parameters, 'code', 256 );
		$verifier = self::requiredParameter( $parameters, 'code_verifier', 128 );
		$redirect = self::requiredParameter( $parameters, 'redirect_uri', 2048 );
		if ( 1 !== preg_match( '/^[A-Za-z0-9\-._~]{43,128}$/D', $verifier ) ) {
			throw new ProtocolException( 'invalid_grant', 'The authorization code or PKCE verifier is invalid.' );
		}

		$timestamp = time();
		$record    = $this->credentials->find( CredentialStore::AUTHORIZATION_CODE, $identity->issuer(), $code );
		$policy    = $this->accessPolicy->forIssuer( $identity->issuer() );
		if (
			null === $record
			|| $record->issuer() !== $identity->issuer()
			|| $record->clientId() !== $client->clientId()
			|| ! $policy->bindingAvailable( $record->resource(), $record->scope() )
			|| ! UserEligibility::isActiveForCurrentSite( $record->userId() )
			|| ( null === $record->consumedAt() && $record->expiresAt() < $timestamp )
			|| ! hash_equals( $record->codeChallenge(), self::s256Challenge( $verifier ) )
		) {
			throw new ProtocolException( 'invalid_grant', 'The authorization code or PKCE verifier is invalid.' );
		}

		if ( $record->redirectUri() !== $redirect ) {
			throw new ProtocolException( 'invalid_grant', 'The authorization code redirect binding is invalid.' );
		}

		if ( array_key_exists( 'resource', $parameters ) && $record->resource() !== self::requiredParameter( $parameters, 'resource', 2048 ) ) {
			throw new ProtocolException( 'invalid_target', 'The requested protected resource is invalid.' );
		}

		$issued = $this->credentials->exchangeAuthorizationCode( $record, $timestamp );
		if ( null === $issued ) {
			throw new ProtocolException( 'invalid_grant', 'The authorization code or PKCE verifier is invalid.' );
		}
		$this->clients->markActivity( $record->issuer(), $record->clientId(), $timestamp );

		return $this->tokenResponse( $issued, $record );
	}

	/**
	 * Rotates one refresh token without expanding its original grant.
	 *
	 * @param array<mixed> $parameters Form parameters.
	 * @param Client       $client Authenticated exact client.
	 * @return array{access_token: string, token_type: string, expires_in: int, scope: string, resource: string, refresh_token: string}
	 * @throws ProtocolException When refresh validation fails.
	 */
	private function exchangeRefreshToken( array $parameters, Client $client ): array {
		$identity = $this->siteState->identity();
		if ( null === $identity ) {
			throw new ProtocolException( 'temporarily_unavailable', 'The OAuth issuer is not enabled.', 503 );
		}

		$presented = self::requiredParameter( $parameters, 'refresh_token', 256 );
		$record    = $this->credentials->find( CredentialStore::REFRESH_TOKEN, $identity->issuer(), $presented );
		$policy    = $this->accessPolicy->forIssuer( $identity->issuer() );
		if (
			null === $record
			|| $record->issuer() !== $identity->issuer()
			|| $record->clientId() !== $client->clientId()
			|| ! $policy->bindingAvailable( $record->resource(), $record->scope() )
			|| ! $record->continuingAccess()
			|| ! UserEligibility::isActiveForCurrentSite( $record->userId() )
		) {
			throw new ProtocolException( 'invalid_grant', 'The refresh token is invalid.' );
		}

		if ( array_key_exists( 'resource', $parameters ) && $record->resource() !== self::requiredParameter( $parameters, 'resource', 2048 ) ) {
			throw new ProtocolException( 'invalid_target', 'The requested protected resource is invalid.' );
		}
		if ( array_key_exists( 'scope', $parameters ) && $record->scope() !== self::requiredParameter( $parameters, 'scope', 1024 ) ) {
			throw new ProtocolException( 'invalid_scope', 'The requested scope exceeds the approved grant.' );
		}

		$timestamp = time();
		$issued    = $this->credentials->rotateRefreshToken( $record, $timestamp );
		if ( null === $issued ) {
			throw new ProtocolException( 'invalid_grant', 'The refresh token is invalid.' );
		}
		$this->clients->markActivity( $record->issuer(), $record->clientId(), $timestamp );

		$response = $this->tokenResponse( $issued, $record );
		if ( ! isset( $response['refresh_token'] ) ) {
			throw new ProtocolException( 'invalid_grant', 'The refresh token is invalid.' );
		}

		return $response;
	}

	/**
	 * Validates an opaque access token against the exact request assignment.
	 *
	 * @since 0.1.0
	 *
	 * @param string        $token Presented bearer token.
	 * @param string        $resourceIdentifier Exact assigned resource.
	 * @param array<string> $requiredScopes Required OAuth scopes.
	 * @throws ProtocolException With invalid_token or insufficient_scope.
	 */
	public function validateAccessToken( string $token, string $resourceIdentifier, array $requiredScopes ): AccessTokenContext {
		$identity = $this->siteState->identity();
		if ( ! $this->siteState->isEnabled() || ! $this->siteState->requestMatchesIdentity() || null === $identity ) {
			throw new ProtocolException( 'invalid_token', 'The access token is invalid.', 401 );
		}
		if ( ! $this->containment->bearerAllowed() ) {
			throw new ProtocolException( 'invalid_token', 'The access token is invalid.', 401 );
		}
		if ( ! $this->signingKeys->credentialOperationsAllowed() ) {
			throw new ProtocolException( 'invalid_token', 'The access token is invalid.', 401 );
		}

		$policy  = $this->accessPolicy->forIssuer( $identity->issuer() );
		$record  = $this->credentials->find( CredentialStore::ACCESS_TOKEN, $identity->issuer(), $token );
		$grantId = null === $record ? null : $record->grantId();
		$grant   = is_int( $grantId ) ? $this->credentials->findGrant( $grantId ) : null;
		if (
			null === $record
			|| null === $grant
			|| ! $record->isActiveAt( time() )
			|| ! $grant->isActiveAt( time() )
			|| $record->issuer() !== $identity->issuer()
			|| ! $policy->assignmentAvailable( $resourceIdentifier, $requiredScopes )
			|| ! $policy->bindingAvailable( $record->resource(), $record->scope() )
			|| $record->resource() !== $resourceIdentifier
			|| $grant->issuer() !== $record->issuer()
			|| $grant->resource() !== $record->resource()
			|| $grant->clientId() !== $record->clientId()
			|| $grant->userId() !== $record->userId()
			|| $grant->scope() !== $record->scope()
			|| ! UserEligibility::isActiveForCurrentSite( $record->userId() )
			|| null === $this->clients->findActive( $record->issuer(), $record->clientId() )
		) {
			throw new ProtocolException( 'invalid_token', 'The access token is invalid.', 401 );
		}

		$scopes = preg_split( '/ +/', trim( $record->scope() ) );
		$scopes = is_array( $scopes ) ? array_values( array_filter( $scopes ) ) : array();
		foreach ( $requiredScopes as $requiredScope ) {
			if ( ! in_array( $requiredScope, $scopes, true ) ) {
				throw new ProtocolException( 'insufficient_scope', 'The access token has insufficient scope.', 403 );
			}
		}

		return new AccessTokenContext(
			$record->issuer(),
			$record->resource(),
			$record->clientId(),
			$record->userId(),
			$scopes
		);
	}

	/**
	 * Produces the RFC 7636 S256 challenge.
	 *
	 * @since 0.1.0
	 *
	 * @param string $verifier PKCE verifier.
	 */
	public static function s256Challenge( string $verifier ): string {
		return rtrim( strtr( base64_encode( hash( 'sha256', $verifier, true ) ), '+/', '-_' ), '=' ); // phpcs:ignore WordPress.PHP.DiscouragedPHPFunctions.obfuscation_base64_encode -- RFC 7636 requires base64url encoding of the SHA-256 digest.
	}

	/**
	 * Returns the complete operator-filtered credential-surface policy.
	 *
	 * @param string $issuer Exact issuer.
	 * @return array<mixed, mixed>
	 * @throws ProtocolException When policy is unavailable.
	 */
	private function rateLimitPolicy( string $issuer ): array {
		$policy = apply_filters( 'charter_oauth_rate_limit_policy', self::DEFAULT_RATE_POLICY, $issuer ); // phpcs:ignore WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedHooknameFound -- Public advanced operator policy hook.
		if ( ! is_array( $policy ) ) {
			throw new ProtocolException( 'temporarily_unavailable', 'The credential processing policy is unavailable.', 503 );
		}

		return $policy;
	}

	/**
	 * Applies one ordinary endpoint budget.
	 *
	 * @param string              $issuer Exact issuer.
	 * @param string              $surface Stable endpoint surface and policy key.
	 * @param string              $subject Non-secret bucket subject.
	 * @param array<mixed, mixed> $policy Complete operator policy.
	 * @param string              $clientId Submitted client identifier.
	 * @param int                 $timestamp Current timestamp.
	 * @throws ProtocolException When policy denies the request.
	 */
	private function enforceRateLimit( string $issuer, string $surface, string $subject, array $policy, string $clientId, int $timestamp ): void {
		$limit = $policy[ $surface ] ?? null;
		if ( ! is_int( $limit ) || 1 > $limit ) {
			throw new ProtocolException( 'temporarily_unavailable', 'The credential processing policy is unavailable.', 503 );
		}
		$decision = $this->rateLimiter->consume( $issuer, $surface, $subject, $limit, MINUTE_IN_SECONDS, $timestamp );
		$this->throwWhenLimited( $decision, $issuer, $surface, $clientId, $timestamp );
	}

	/**
	 * Applies the failure-specific progressive token backoff.
	 *
	 * @param string              $issuer Exact issuer.
	 * @param string              $surface Stable failure surface and policy key.
	 * @param string              $subject Non-secret bucket subject.
	 * @param array<mixed, mixed> $policy Complete operator policy.
	 * @param string              $clientId Submitted client identifier.
	 * @param int                 $timestamp Current timestamp.
	 * @throws ProtocolException When policy denies the request.
	 */
	private function enforceFailureBackoff( string $issuer, string $surface, string $subject, array $policy, string $clientId, int $timestamp ): void {
		$limit = $policy[ $surface ] ?? null;
		if ( ! is_int( $limit ) || 1 > $limit ) {
			throw new ProtocolException( 'temporarily_unavailable', 'The credential processing policy is unavailable.', 503 );
		}
		$decision = $this->rateLimiter->consumeWithBackoff( $issuer, $surface, $subject, $limit, MINUTE_IN_SECONDS, 15 * MINUTE_IN_SECONDS, $timestamp );
		$this->throwWhenLimited( $decision, $issuer, $surface, $clientId, $timestamp );
	}

	/**
	 * Converts a denied atomic counter into one generic OAuth result.
	 *
	 * @param RateLimitDecision $decision Atomic counter outcome.
	 * @param string            $issuer Exact issuer.
	 * @param string            $surface Stable endpoint surface.
	 * @param string            $clientId Submitted client identifier.
	 * @param int               $timestamp Current timestamp.
	 * @throws ProtocolException When the request is limited.
	 */
	private function throwWhenLimited( RateLimitDecision $decision, string $issuer, string $surface, string $clientId, int $timestamp ): void {
		if ( $decision->allowed() ) {
			return;
		}
		if ( $decision->count() === $decision->limit() + 1 ) {
			$this->audit->record( $issuer, 'rate_limit_escalated', 'blocked', $surface, null, null, $clientId, SourceAddress::current(), $timestamp );
		}

		throw new ProtocolException( 'temporarily_unavailable', 'Too many credential requests.', 429, null, null, $decision->retryAfter() ); // phpcs:ignore WordPress.Security.EscapeOutput.ExceptionNotEscaped -- Typed retry metadata is not rendered here.
	}

	/**
	 * Projects one common no-claim opaque-token response.
	 *
	 * @param array{access_token: string, refresh_token?: string} $issued Issued opaque values.
	 * @param CredentialRecord                                    $record Exact grant binding.
	 * @return array{access_token: string, token_type: string, expires_in: int, scope: string, resource: string, refresh_token?: string}
	 */
	private function tokenResponse( array $issued, CredentialRecord $record ): array {
		$response = array(
			'access_token' => $issued['access_token'],
			'token_type'   => 'Bearer',
			'expires_in'   => 3600,
			'scope'        => $record->scope(),
			'resource'     => $record->resource(),
		);
		if ( isset( $issued['refresh_token'] ) ) {
			$response['refresh_token'] = $issued['refresh_token'];
		}

		return $response;
	}

	/**
	 * Reads one required bounded scalar token parameter.
	 *
	 * @param array<mixed> $parameters Request parameters.
	 * @param string       $name Parameter name.
	 * @param int          $maxLength Maximum byte length.
	 * @throws ProtocolException When the value is absent or invalid.
	 */
	private static function requiredParameter( array $parameters, string $name, int $maxLength ): string {
		$value = $parameters[ $name ] ?? null;
		if ( ! is_string( $value ) || '' === $value || strlen( $value ) > $maxLength ) {
			throw new ProtocolException( 'invalid_request', 'A required token parameter is invalid.' );
		}

		return $value;
	}
}
