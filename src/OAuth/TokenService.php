<?php
/**
 * OAuth token exchange, refresh, and validation.
 *
 * @package GalatanOvidiu\Charter
 */

declare(strict_types=1);

namespace GalatanOvidiu\Charter\OAuth;

use GalatanOvidiu\Charter\Site\SiteState;

/**
 * Executes exact client-bound token lifecycle operations.
 *
 * @since 0.1.0
 */
final class TokenService {

	private const REVOCABLE_TOKEN_TYPES = array(
		CredentialStore::ACCESS_TOKEN,
		CredentialStore::REFRESH_TOKEN,
	);

	/**
	 * Creates the token service.
	 *
	 * @since 0.1.0
	 *
	 * @param SiteState       $siteState Site lifecycle and identity.
	 * @param ClientRegistry  $clients Client registry.
	 * @param CredentialStore $credentials Grant and credential persistence.
	 */
	public function __construct(
		private readonly SiteState $siteState,
		private readonly ClientRegistry $clients,
		private readonly CredentialStore $credentials
	) {
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

		$grantType       = self::requiredParameter( $parameters, 'grant_type', 64 );
		$clientId        = self::requiredParameter( $parameters, 'client_id', 2048 );
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

		return match ( $grantType ) {
			Client::GRANT_AUTHORIZATION_CODE => $this->exchangeAuthorizationCode( $parameters, $client ),
			Client::GRANT_REFRESH_TOKEN => $this->exchangeRefreshToken( $parameters, $client ),
			default => throw new ProtocolException( 'unsupported_grant_type', 'The requested grant type is not supported.' ),
		};
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

		$clientId        = self::requiredParameter( $parameters, 'client_id', 2048 );
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
		if ( 1 !== preg_match( '/^[A-Za-z0-9\-._~]{43,128}$/D', $verifier ) ) {
			throw new ProtocolException( 'invalid_grant', 'The authorization code or PKCE verifier is invalid.' );
		}

		$timestamp = time();
		$record    = $this->credentials->find( CredentialStore::AUTHORIZATION_CODE, $identity->issuer(), $code );
		if (
			null === $record
			|| $record->issuer() !== $identity->issuer()
			|| $record->resource() !== $identity->issuer()
			|| $record->clientId() !== $client->clientId()
			|| $record->scope() !== AuthorizationService::GENERAL_SCOPE
			|| ! UserEligibility::isActiveForCurrentSite( $record->userId() )
			|| ( null === $record->consumedAt() && $record->expiresAt() < $timestamp )
			|| ! hash_equals( $record->codeChallenge(), self::s256Challenge( $verifier ) )
		) {
			throw new ProtocolException( 'invalid_grant', 'The authorization code or PKCE verifier is invalid.' );
		}

		if ( array_key_exists( 'redirect_uri', $parameters ) && $record->redirectUri() !== self::requiredParameter( $parameters, 'redirect_uri', 2048 ) ) {
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
		if (
			null === $record
			|| $record->issuer() !== $identity->issuer()
			|| $record->resource() !== $identity->issuer()
			|| $record->clientId() !== $client->clientId()
			|| $record->scope() !== AuthorizationService::GENERAL_SCOPE
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

		$record  = $this->credentials->find( CredentialStore::ACCESS_TOKEN, $identity->issuer(), $token );
		$grantId = null === $record ? null : $record->grantId();
		$grant   = is_int( $grantId ) ? $this->credentials->findGrant( $grantId ) : null;
		if (
			null === $record
			|| null === $grant
			|| ! $record->isActiveAt( time() )
			|| ! $grant->isActiveAt( time() )
			|| $record->issuer() !== $identity->issuer()
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
