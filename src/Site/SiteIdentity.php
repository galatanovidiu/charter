<?php
/**
 * Canonical OAuth site identity.
 *
 * @package GalatanOvidiu\Charter
 */

declare(strict_types=1);

namespace GalatanOvidiu\Charter\Site;

use InvalidArgumentException;

/**
 * Validates and carries one canonical bare-origin issuer.
 *
 * @since 0.1.0
 */
final class SiteIdentity {

	/**
	 * Creates an identity from a configured public URL.
	 *
	 * @since 0.1.0
	 *
	 * @param string        $url              Candidate canonical public URL.
	 * @param bool          $developmentMode  Whether explicit development HTTP is enabled.
	 * @param array<string> $developmentHosts Exact additional development HTTP hosts.
	 * @throws InvalidArgumentException When the URL cannot identify a supported v1 issuer.
	 */
	public static function fromUrl( string $url, bool $developmentMode = false, array $developmentHosts = array() ): self {
		$parts = parse_url( $url ); // phpcs:ignore WordPress.WP.AlternativeFunctions.parse_url_parse_url -- This pure value object is used without a loaded WordPress runtime.

		if (
			false === $parts
			|| ! is_string( $parts['scheme'] ?? null )
			|| ! is_string( $parts['host'] ?? null )
			|| '' === $parts['host']
			|| isset( $parts['user'] )
			|| isset( $parts['pass'] )
			|| isset( $parts['query'] )
			|| isset( $parts['fragment'] )
			|| ! in_array( $parts['path'] ?? '', array( '', '/' ), true )
		) {
			throw new InvalidArgumentException( 'charter_issuer_must_be_bare_origin' );
		}

		$scheme = strtolower( $parts['scheme'] );
		$host   = strtolower( $parts['host'] );

		if ( 'https' !== $scheme && ! self::allowsDevelopmentHttp( $scheme, $host, $developmentMode, $developmentHosts ) ) {
			throw new InvalidArgumentException( 'charter_issuer_requires_https' );
		}

		$port = is_int( $parts['port'] ?? null ) ? $parts['port'] : null;
		if ( ( 'https' === $scheme && 443 === $port ) || ( 'http' === $scheme && 80 === $port ) ) {
			$port = null;
		}

		$displayHost = str_contains( $host, ':' ) && ! str_starts_with( $host, '[' ) ? '[' . $host . ']' : $host;
		$issuer      = $scheme . '://' . $displayHost . ( null === $port ? '' : ':' . $port );

		return new self( $issuer );
	}

	/**
	 * Returns the exact canonical issuer and default resource identifier.
	 *
	 * @since 0.1.0
	 */
	public function issuer(): string {
		return $this->issuer;
	}

	/**
	 * Creates the immutable identity.
	 *
	 * @since 0.1.0
	 *
	 * @param string $issuer Canonical issuer.
	 */
	private function __construct(
		private readonly string $issuer
	) {
	}

	/**
	 * Applies the explicit local-development HTTP policy.
	 *
	 * @since 0.1.0
	 *
	 * @param string        $scheme           Candidate scheme.
	 * @param string        $host             Candidate host.
	 * @param bool          $developmentMode  Whether development mode is enabled.
	 * @param array<string> $developmentHosts Exact configured development hosts.
	 */
	private static function allowsDevelopmentHttp(
		string $scheme,
		string $host,
		bool $developmentMode,
		array $developmentHosts
	): bool {
		if ( ! $developmentMode || 'http' !== $scheme ) {
			return false;
		}

		if ( in_array( $host, array( 'localhost', '127.0.0.1', '::1', '[::1]' ), true ) ) {
			return true;
		}

		return in_array( $host, array_map( 'strtolower', $developmentHosts ), true );
	}
}
