<?php
/**
 * Pre-registered OAuth client.
 *
 * @package GalatanOvidiu\Charter
 */

declare(strict_types=1);

namespace GalatanOvidiu\Charter\OAuth;

/**
 * Carries one active OAuth client registration.
 *
 * @since 0.1.0
 */
final class Client {

	public const AUTH_NONE               = 'none';
	public const AUTH_CLIENT_SECRET_POST = 'client_secret_post';

	public const GRANT_AUTHORIZATION_CODE = 'authorization_code';
	public const GRANT_REFRESH_TOKEN      = 'refresh_token';

	/**
	 * Creates a client registration value.
	 *
	 * @since 0.1.0
	 *
	 * @param string        $issuer       Exact owning issuer.
	 * @param string        $clientId     Exact client identifier.
	 * @param string        $name         User-facing client name.
	 * @param array<string> $redirectUris Registered redirect URIs.
	 * @param string        $authenticationMethod Token-endpoint authentication method.
	 * @param array<string> $grantTypes Supported grant types.
	 * @param string|null   $clientSecretHash One-way confidential-client secret hash.
	 * @param string        $source Registration source.
	 * @param string        $metadataFingerprint Security metadata fingerprint.
	 */
	public function __construct(
		private readonly string $issuer,
		private readonly string $clientId,
		private readonly string $name,
		private readonly array $redirectUris,
		private readonly string $authenticationMethod = self::AUTH_NONE,
		private readonly array $grantTypes = array( self::GRANT_AUTHORIZATION_CODE ),
		private readonly ?string $clientSecretHash = null,
		private readonly string $source = ClientRegistry::SOURCE_PRE_REGISTERED,
		private readonly string $metadataFingerprint = ''
	) {
	}

	/**
	 * Returns the exact owning issuer.
	 *
	 * @since 0.1.0
	 */
	public function issuer(): string {
		return $this->issuer;
	}

	/**
	 * Returns the exact client identifier.
	 *
	 * @since 0.1.0
	 */
	public function clientId(): string {
		return $this->clientId;
	}

	/**
	 * Returns the display name.
	 *
	 * @since 0.1.0
	 */
	public function name(): string {
		return $this->name;
	}

	/**
	 * Returns registered redirect URIs.
	 *
	 * @since 0.1.0
	 *
	 * @return array<string> Exact registered values.
	 */
	public function redirectUris(): array {
		return $this->redirectUris;
	}

	/**
	 * Returns the one supported token-endpoint authentication method.
	 *
	 * @since 0.1.0
	 */
	public function authenticationMethod(): string {
		return $this->authenticationMethod;
	}

	/**
	 * Returns the onboarding source.
	 *
	 * @since 0.1.0
	 */
	public function source(): string {
		return $this->source;
	}

	/**
	 * Returns the security metadata fingerprint used by consent reuse.
	 *
	 * @since 0.1.0
	 */
	public function metadataFingerprint(): string {
		return $this->metadataFingerprint;
	}

	/**
	 * Reports whether the client declared one supported grant type.
	 *
	 * @since 0.1.0
	 *
	 * @param string $grantType OAuth grant type.
	 */
	public function supportsGrantType( string $grantType ): bool {
		return in_array( $grantType, $this->grantTypes, true );
	}

	/**
	 * Authenticates a confidential client without exposing its stored hash.
	 *
	 * @since 0.1.0
	 *
	 * @param string $clientSecret Presented client secret.
	 */
	public function authenticatesClientSecret( string $clientSecret ): bool {
		return self::AUTH_CLIENT_SECRET_POST === $this->authenticationMethod
			&& is_string( $this->clientSecretHash )
			&& '' !== $clientSecret
			&& password_verify( $clientSecret, $this->clientSecretHash );
	}

	/**
	 * Reports whether a requested redirect is registered.
	 *
	 * Native loopback redirects may vary only their runtime port.
	 *
	 * @since 0.1.0
	 *
	 * @param string $requestedUri Requested redirect URI.
	 */
	public function allowsRedirectUri( string $requestedUri ): bool {
		foreach ( $this->redirectUris as $registeredUri ) {
			if ( $registeredUri === $requestedUri || self::matchesLoopbackPort( $registeredUri, $requestedUri ) ) {
				return true;
			}
		}

		return false;
	}

	/**
	 * Matches the native loopback exception without relaxing any other component.
	 *
	 * @since 0.1.0
	 *
	 * @param string $registeredUri Registered URI.
	 * @param string $requestedUri  Requested URI.
	 */
	private static function matchesLoopbackPort( string $registeredUri, string $requestedUri ): bool {
		$registered = parse_url( $registeredUri ); // phpcs:ignore WordPress.WP.AlternativeFunctions.parse_url_parse_url -- This pure value object is used without a loaded WordPress runtime.
		$requested  = parse_url( $requestedUri ); // phpcs:ignore WordPress.WP.AlternativeFunctions.parse_url_parse_url -- This pure value object is used without a loaded WordPress runtime.

		if ( false === $registered || false === $requested ) {
			return false;
		}

		$registeredHost = strtolower( (string) ( $registered['host'] ?? '' ) );
		$requestedHost  = strtolower( (string) ( $requested['host'] ?? '' ) );
		if (
			'http' !== strtolower( (string) ( $registered['scheme'] ?? '' ) )
			|| 'http' !== strtolower( (string) ( $requested['scheme'] ?? '' ) )
			|| ! in_array( $registeredHost, array( '127.0.0.1', '::1', '[::1]' ), true )
			|| $registeredHost !== $requestedHost
		) {
			return false;
		}

		unset( $registered['port'], $requested['port'] );

		return $registered === $requested;
	}
}
