<?php
/**
 * Disposable Slice 0 discovery metadata projector.
 *
 * @package GalatanOvidiu\Charter
 */

declare(strict_types=1);

namespace GalatanOvidiu\Charter\Tests\Prototype\DiscoveryPublication;

use InvalidArgumentException;

/**
 * Projects exact proof metadata from already-established identities.
 *
 * @since 0.1.0
 */
final class MetadataProjector {

	/**
	 * Returns the exact RFC 8414 metadata URL for one supported issuer.
	 *
	 * @since 0.1.0
	 *
	 * @param string $issuer The exact established issuer.
	 * @return string The metadata URL.
	 */
	public static function authorizationServerUrl( string $issuer ): string {
		self::assertBareOriginIssuer( $issuer );

		return $issuer . '/.well-known/oauth-authorization-server';
	}

	/**
	 * Returns the exact RFC 8414 proof projection.
	 *
	 * @since 0.1.0
	 *
	 * @param string $issuer The exact established issuer.
	 * @return array<string, string|list<string>> The proof metadata.
	 */
	public static function authorizationServerMetadata( string $issuer ): array {
		self::assertBareOriginIssuer( $issuer );

		return array(
			'issuer'                                     => $issuer,
			'authorization_endpoint'                     => $issuer . '/charter-proof/authorize',
			'token_endpoint'                             => $issuer . '/charter-proof/token',
			'registration_endpoint'                      => $issuer . '/charter-proof/register',
			'revocation_endpoint'                        => $issuer . '/charter-proof/revoke',
			'response_types_supported'                   => array( 'code' ),
			'response_modes_supported'                   => array( 'query' ),
			'grant_types_supported'                      => array( 'authorization_code', 'refresh_token' ),
			'token_endpoint_auth_methods_supported'      => array( 'none', 'client_secret_post' ),
			'revocation_endpoint_auth_methods_supported' => array( 'none', 'client_secret_post' ),
			'code_challenge_methods_supported'           => array( 'S256' ),
			'scopes_supported'                           => array( 'wordpress:access', 'offline_access' ),
		);
	}

	/**
	 * Returns the exact RFC 9728 metadata URL for one resource.
	 *
	 * @since 0.1.0
	 *
	 * @param string $issuer            The exact established issuer.
	 * @param string $protectedResource The exact established resource.
	 * @return string The metadata URL.
	 */
	public static function protectedResourceUrl( string $issuer, string $protectedResource ): string {
		self::assertBareOriginIssuer( $issuer );
		$resourcePath = self::resourcePath( $issuer, $protectedResource );

		return $issuer . '/.well-known/oauth-protected-resource' . $resourcePath;
	}

	/**
	 * Returns the exact RFC 9728 proof projection for one resource.
	 *
	 * @since 0.1.0
	 *
	 * @param string $issuer            The exact established issuer.
	 * @param string $protectedResource The exact established resource.
	 * @return array{resource: string, authorization_servers: list<string>} The proof metadata.
	 */
	public static function protectedResourceMetadata( string $issuer, string $protectedResource ): array {
		self::protectedResourceUrl( $issuer, $protectedResource );

		return array(
			'resource'              => $protectedResource,
			'authorization_servers' => array( $issuer ),
		);
	}

	/**
	 * Selects metadata only for an exact standards-derived request path.
	 *
	 * @since 0.1.0
	 *
	 * @param string $issuer    The exact established issuer.
	 * @param array  $resources The isolated resources.
	 * @param string $path      The exact request path.
	 * @return array<string, string|list<string>>|null The selected metadata or null.
	 */
	public static function metadataForPath( string $issuer, array $resources, string $path ): ?array {
		$metadataByPath = array(
			'/.well-known/oauth-authorization-server' => self::authorizationServerMetadata( $issuer ),
			'/.well-known/oauth-protected-resource'   => self::protectedResourceMetadata( $issuer, $issuer ),
		);

		foreach ( $resources as $protectedResource ) {
			$metadataUrl  = self::protectedResourceUrl( $issuer, $protectedResource );
			$resourcePath = substr( $metadataUrl, strlen( $issuer ) );

			$metadataByPath[ $resourcePath ] = self::protectedResourceMetadata( $issuer, $protectedResource );
		}

		return $metadataByPath[ $path ] ?? null;
	}

	/**
	 * Requires the exact established v1 issuer form without normalizing it.
	 *
	 * @since 0.1.0
	 *
	 * @param string $issuer The candidate issuer.
	 * @throws InvalidArgumentException When the issuer is not an exact HTTPS bare origin.
	 */
	private static function assertBareOriginIssuer( string $issuer ): void {
		// phpcs:ignore WordPress.WP.AlternativeFunctions.parse_url_parse_url -- This pure proof class also runs outside WordPress.
		$parts = parse_url( $issuer );

		if (
			! is_array( $parts )
			|| 'https' !== ( $parts['scheme'] ?? null )
			|| ! is_string( $parts['host'] ?? null )
			|| '' === $parts['host']
			|| isset( $parts['user'] )
			|| isset( $parts['pass'] )
			|| isset( $parts['query'] )
			|| isset( $parts['fragment'] )
			|| isset( $parts['path'] )
		) {
			throw new InvalidArgumentException( 'The proof issuer must be an exact HTTPS bare origin.' );
		}

		$expected = 'https://' . $parts['host'];

		if ( isset( $parts['port'] ) ) {
			if ( ! is_int( $parts['port'] ) || $parts['port'] < 1 || $parts['port'] > 65535 ) {
				throw new InvalidArgumentException( 'The proof issuer port is invalid.' );
			}

			$expected .= ':' . $parts['port'];
		}

		if ( $issuer !== $expected ) {
			throw new InvalidArgumentException( 'The proof issuer must already be in its exact established form.' );
		}
	}

	/**
	 * Returns the resource path after exact same-origin validation.
	 *
	 * @since 0.1.0
	 *
	 * @param string $issuer            The exact established issuer.
	 * @param string $protectedResource The exact established resource.
	 * @return string The empty default path or exact isolated path.
	 * @throws InvalidArgumentException When the resource is not an exact same-origin path resource.
	 */
	private static function resourcePath( string $issuer, string $protectedResource ): string {
		if ( $protectedResource === $issuer ) {
			return '';
		}

		// phpcs:ignore WordPress.WP.AlternativeFunctions.parse_url_parse_url -- This pure proof class also runs outside WordPress.
		$parts = parse_url( $protectedResource );

		if (
			! is_array( $parts )
			|| isset( $parts['user'] )
			|| isset( $parts['pass'] )
			|| isset( $parts['query'] )
			|| isset( $parts['fragment'] )
			|| ! is_string( $parts['path'] ?? null )
			|| '/' === $parts['path']
			|| ! str_starts_with( $parts['path'], '/' )
			|| str_contains( $parts['path'], '//' )
			|| str_contains( $parts['path'], '%' )
		) {
			throw new InvalidArgumentException( 'The proof resource must be an exact same-origin path resource.' );
		}

		$pathSegments = explode( '/', trim( $parts['path'], '/' ) );

		if ( in_array( '.', $pathSegments, true ) || in_array( '..', $pathSegments, true ) ) {
			throw new InvalidArgumentException( 'The proof resource path cannot contain dot segments.' );
		}

		$resourceOrigin = ( $parts['scheme'] ?? '' ) . '://' . ( $parts['host'] ?? '' );

		if ( isset( $parts['port'] ) ) {
			$resourceOrigin .= ':' . $parts['port'];
		}

		if ( $issuer !== $resourceOrigin || $protectedResource !== $resourceOrigin . $parts['path'] ) {
			throw new InvalidArgumentException( 'The proof resource must use the exact established issuer origin.' );
		}

		return $parts['path'];
	}
}
