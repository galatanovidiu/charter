<?php
/**
 * Pre-registered OAuth client persistence.
 *
 * @package GalatanOvidiu\Charter
 */

declare(strict_types=1);

namespace GalatanOvidiu\Charter\OAuth;

use InvalidArgumentException;

/**
 * Stores immutable client security identities per exact issuer.
 *
 * @since 0.1.0
 */
final class ClientRegistry {

	private const OPTION = 'charter_oauth_clients';

	/**
	 * Registers one public client without a secret.
	 *
	 * Re-registering the same exact record is idempotent. Changing redirect
	 * identity requires a new client identifier.
	 *
	 * @since 0.1.0
	 *
	 * @param string        $issuer       Exact issuer.
	 * @param string        $clientId     Exact client identifier.
	 * @param string        $name         User-facing client name.
	 * @param array<string> $redirectUris Exact allowed redirects.
	 * @param bool          $supportsRefresh Whether the client declares refresh support.
	 * @return bool Whether the registration was persisted.
	 * @throws InvalidArgumentException When registration input is invalid or changes an existing identity.
	 */
	public function registerPublicClient( string $issuer, string $clientId, string $name, array $redirectUris, bool $supportsRefresh = false ): bool {
		$record   = $this->registrationRecord(
			$issuer,
			$clientId,
			$name,
			$redirectUris,
			Client::AUTH_NONE,
			$supportsRefresh,
			null
		);
		$key      = self::key( $issuer, $clientId );
		$records  = $this->records();
		$existing = $records[ $key ] ?? null;

		if ( is_array( $existing ) ) {
			if ( $this->normalizeRecord( $existing ) !== $record ) {
				throw new InvalidArgumentException( 'charter_client_identity_change_requires_new_id' );
			}

			return true;
		}

		$records[ $key ] = $record;

		return update_option( self::OPTION, $records, false );
	}

	/**
	 * Registers one confidential client and returns its secret exactly once.
	 *
	 * @since 0.1.0
	 *
	 * @param string        $issuer       Exact issuer.
	 * @param string        $clientId     Exact client identifier.
	 * @param string        $name         User-facing client name.
	 * @param array<string> $redirectUris Exact allowed redirects.
	 * @param bool          $supportsRefresh Whether the client declares refresh support.
	 * @throws InvalidArgumentException When input is invalid or the client identifier exists.
	 * @throws \RuntimeException When a secure secret cannot be generated or persisted.
	 */
	public function registerConfidentialClient( string $issuer, string $clientId, string $name, array $redirectUris, bool $supportsRefresh = true ): string {
		$key     = self::key( $issuer, $clientId );
		$records = $this->records();
		if ( isset( $records[ $key ] ) ) {
			throw new InvalidArgumentException( 'charter_client_identity_change_requires_new_id' );
		}

		$secret = 'chs_' . self::base64UrlEncode( random_bytes( 32 ) );
		$hash   = password_hash( $secret, PASSWORD_DEFAULT );

		$records[ $key ] = $this->registrationRecord(
			$issuer,
			$clientId,
			$name,
			$redirectUris,
			Client::AUTH_CLIENT_SECRET_POST,
			$supportsRefresh,
			$hash
		);
		if ( ! update_option( self::OPTION, $records, false ) ) {
			throw new \RuntimeException( 'charter_client_registration_failed' );
		}

		return $secret;
	}

	/**
	 * Finds one active exact client registration.
	 *
	 * @since 0.1.0
	 *
	 * @param string $issuer   Exact issuer.
	 * @param string $clientId Exact client identifier.
	 */
	public function findActive( string $issuer, string $clientId ): ?Client {
		$record = $this->records()[ self::key( $issuer, $clientId ) ] ?? null;

		if (
			! is_array( $record )
			|| 'active' !== ( $record['status'] ?? null )
			|| ( $record['issuer'] ?? null ) !== $issuer
			|| ( $record['client_id'] ?? null ) !== $clientId
			|| ! is_string( $record['name'] ?? null )
			|| ! is_array( $record['redirect_uris'] ?? null )
		) {
			return null;
		}

		$record = $this->normalizeRecord( $record );
		if ( null === $record ) {
			return null;
		}

		return new Client(
			$issuer,
			$clientId,
			$record['name'],
			$record['redirect_uris'],
			$record['token_endpoint_auth_method'],
			$record['grant_types'],
			$record['client_secret_hash']
		);
	}

	/**
	 * Authenticates one exact active client for a token-like endpoint.
	 *
	 * @since 0.1.0
	 *
	 * @param string      $issuer          Exact issuer.
	 * @param string      $clientId        Presented client identifier.
	 * @param bool        $secretPresented Whether client_secret was present in the request.
	 * @param string|null $clientSecret    Presented secret when present.
	 */
	public function authenticateForTokenEndpoint( string $issuer, string $clientId, bool $secretPresented, ?string $clientSecret ): ?Client {
		$client = $this->findActive( $issuer, $clientId );
		if ( null === $client ) {
			if ( $secretPresented && is_string( $clientSecret ) && '' !== $clientSecret ) {
				password_verify( $clientSecret, '$2y$10$usesomesillystringfore7hnbRJHxXVLeakoG8K30oukPsA.ztMG' );
			}

			return null;
		}

		if ( Client::AUTH_NONE === $client->authenticationMethod() ) {
			return $secretPresented ? null : $client;
		}

		if ( ! $secretPresented || ! is_string( $clientSecret ) || strlen( $clientSecret ) > 256 ) {
			return null;
		}

		return $client->authenticatesClientSecret( $clientSecret ) ? $client : null;
	}

	/**
	 * Deletes all client registrations during tests or uninstall.
	 *
	 * @since 0.1.0
	 */
	public function deleteAll(): void {
		delete_option( self::OPTION );
	}

	/**
	 * Validates one production redirect URI class.
	 *
	 * @since 0.1.0
	 *
	 * @param string $uri Candidate redirect URI.
	 */
	private static function isValidRedirectUri( string $uri ): bool {
		if ( strlen( $uri ) > 2048 ) {
			return false;
		}

		$parts = wp_parse_url( $uri );
		if (
			false === $parts
			|| ! is_string( $parts['scheme'] ?? null )
			|| ! is_string( $parts['host'] ?? null )
			|| '' === $parts['host']
			|| isset( $parts['user'] )
			|| isset( $parts['pass'] )
			|| isset( $parts['fragment'] )
		) {
			return false;
		}

		$scheme = strtolower( $parts['scheme'] );
		$host   = strtolower( $parts['host'] );

		return 'https' === $scheme
			|| ( 'http' === $scheme && in_array( $host, array( '127.0.0.1', '::1', '[::1]' ), true ) );
	}

	/**
	 * Builds one validated immutable registration record.
	 *
	 * @since 0.1.0
	 *
	 * @param string        $issuer Exact issuer.
	 * @param string        $clientId Exact client identifier.
	 * @param string        $name Display name.
	 * @param array<string> $redirectUris Exact redirects.
	 * @param string        $authenticationMethod Token endpoint method.
	 * @param bool          $supportsRefresh Whether refresh is declared.
	 * @param string|null   $clientSecretHash One-way secret hash.
	 * @return array{issuer: string, client_id: string, name: string, redirect_uris: array<string>, status: string, token_endpoint_auth_method: string, grant_types: array<string>, client_secret_hash: string|null}
	 * @throws InvalidArgumentException When the registration is invalid.
	 */
	private function registrationRecord( string $issuer, string $clientId, string $name, array $redirectUris, string $authenticationMethod, bool $supportsRefresh, ?string $clientSecretHash ): array {
		if ( '' === $issuer || '' === $clientId || strlen( $clientId ) > 2048 || '' === trim( $name ) || array() === $redirectUris ) {
			throw new InvalidArgumentException( 'charter_client_registration_invalid' );
		}

		$redirectUris = array_values( array_unique( $redirectUris ) );
		foreach ( $redirectUris as $redirectUri ) {
			if ( ! self::isValidRedirectUri( $redirectUri ) ) {
				throw new InvalidArgumentException( 'charter_client_redirect_invalid' );
			}
		}

		if (
			! in_array( $authenticationMethod, array( Client::AUTH_NONE, Client::AUTH_CLIENT_SECRET_POST ), true )
			|| ( Client::AUTH_NONE === $authenticationMethod && null !== $clientSecretHash )
			|| ( Client::AUTH_CLIENT_SECRET_POST === $authenticationMethod && ! is_string( $clientSecretHash ) )
		) {
			throw new InvalidArgumentException( 'charter_client_registration_invalid' );
		}

		$grantTypes = array( Client::GRANT_AUTHORIZATION_CODE );
		if ( $supportsRefresh ) {
			$grantTypes[] = Client::GRANT_REFRESH_TOKEN;
		}

		return array(
			'issuer'                     => $issuer,
			'client_id'                  => $clientId,
			'name'                       => trim( $name ),
			'redirect_uris'              => $redirectUris,
			'status'                     => 'active',
			'token_endpoint_auth_method' => $authenticationMethod,
			'grant_types'                => $grantTypes,
			'client_secret_hash'         => $clientSecretHash,
		);
	}

	/**
	 * Normalizes the initial public-only record shape and rejects corruption.
	 *
	 * @since 0.1.0
	 *
	 * @param array<mixed> $record Stored record.
	 * @return array{issuer: string, client_id: string, name: string, redirect_uris: array<string>, status: string, token_endpoint_auth_method: string, grant_types: array<string>, client_secret_hash: string|null}|null
	 */
	private function normalizeRecord( array $record ): ?array {
		$issuer       = $record['issuer'] ?? null;
		$clientId     = $record['client_id'] ?? null;
		$name         = $record['name'] ?? null;
		$redirectUris = $record['redirect_uris'] ?? null;
		$status       = $record['status'] ?? null;
		$method       = $record['token_endpoint_auth_method'] ?? Client::AUTH_NONE;
		$grantTypes   = $record['grant_types'] ?? array( Client::GRANT_AUTHORIZATION_CODE );
		$secretHash   = $record['client_secret_hash'] ?? null;
		if (
			! is_string( $issuer )
			|| ! is_string( $clientId )
			|| ! is_string( $name )
			|| ! is_array( $redirectUris )
			|| 'active' !== $status
			|| ! is_string( $method )
			|| ! is_array( $grantTypes )
			|| ( null !== $secretHash && ! is_string( $secretHash ) )
		) {
			return null;
		}

		$redirectUris = array_values( array_filter( $redirectUris, 'is_string' ) );
		$grantTypes   = array_values( array_filter( $grantTypes, 'is_string' ) );
		if (
			array() === $redirectUris
			|| ! in_array( Client::GRANT_AUTHORIZATION_CODE, $grantTypes, true )
			|| array() !== array_diff( $grantTypes, array( Client::GRANT_AUTHORIZATION_CODE, Client::GRANT_REFRESH_TOKEN ) )
			|| ( Client::AUTH_NONE === $method && null !== $secretHash )
			|| ( Client::AUTH_CLIENT_SECRET_POST === $method && null === $secretHash )
			|| ! in_array( $method, array( Client::AUTH_NONE, Client::AUTH_CLIENT_SECRET_POST ), true )
		) {
			return null;
		}

		return array(
			'issuer'                     => $issuer,
			'client_id'                  => $clientId,
			'name'                       => $name,
			'redirect_uris'              => $redirectUris,
			'status'                     => 'active',
			'token_endpoint_auth_method' => $method,
			'grant_types'                => $grantTypes,
			'client_secret_hash'         => $secretHash,
		);
	}

	/**
	 * Encodes a one-time generated secret without padding.
	 *
	 * @since 0.1.0
	 *
	 * @param string $bytes Random bytes.
	 */
	private static function base64UrlEncode( string $bytes ): string {
		return rtrim( strtr( base64_encode( $bytes ), '+/', '-_' ), '=' ); // phpcs:ignore WordPress.PHP.DiscouragedPHPFunctions.obfuscation_base64_encode -- RFC 4648 URL-safe encoding of random secret bytes, not code obfuscation.
	}

	/**
	 * Returns the collision-resistant storage key for an issuer/client pair.
	 *
	 * @since 0.1.0
	 *
	 * @param string $issuer   Exact issuer.
	 * @param string $clientId Exact client identifier.
	 */
	private static function key( string $issuer, string $clientId ): string {
		return hash( 'sha256', strlen( $issuer ) . ':' . $issuer . strlen( $clientId ) . ':' . $clientId );
	}

	/**
	 * Reads persisted registrations.
	 *
	 * @since 0.1.0
	 *
	 * @return array<string, mixed> Persisted records.
	 */
	private function records(): array {
		$records = get_option( self::OPTION, array() );
		if ( ! is_array( $records ) ) {
			return array();
		}

		$normalized = array();
		foreach ( $records as $key => $record ) {
			if ( is_string( $key ) ) {
				$normalized[ $key ] = $record;
			}
		}

		return $normalized;
	}
}
