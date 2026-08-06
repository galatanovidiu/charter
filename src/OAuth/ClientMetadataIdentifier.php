<?php
/**
 * Exact Client ID Metadata Document identifier.
 *
 * @package GalatanOvidiu\Charter
 */

declare(strict_types=1);

namespace GalatanOvidiu\Charter\OAuth;

use InvalidArgumentException;

/**
 * Preserves the submitted client identity while exposing only safe fetch parts.
 *
 * @since 0.1.0
 */
final class ClientMetadataIdentifier {

	/**
	 * Creates one validated identifier.
	 *
	 * @param string $exact Exact submitted identity.
	 * @param string $host Validated DNS host.
	 */
	private function __construct(
		private readonly string $exact,
		private readonly string $host
	) {
	}

	/**
	 * Validates the deliberately strict production CIMD URL profile.
	 *
	 * @param string $submitted Exact submitted client identifier.
	 * @throws InvalidArgumentException When the identifier is not fetchable safely.
	 */
	public static function fromString( string $submitted ): self {
		if (
			'' === $submitted
			|| 2048 < strlen( $submitted )
			|| 1 === preg_match( '/[\x00-\x20\x7f]/', $submitted )
			|| str_contains( $submitted, '\\' )
			|| 1 === preg_match( '/%(?![0-9A-Fa-f]{2})/', $submitted )
		) {
			throw new InvalidArgumentException( 'charter_cimd_identifier_invalid' );
		}

		$parts = parse_url( $submitted ); // phpcs:ignore WordPress.WP.AlternativeFunctions.parse_url_parse_url -- This pure identifier boundary is also used without a loaded WordPress runtime.
		if (
			false === $parts
			|| ! is_string( $parts['scheme'] ?? null )
			|| 0 !== strcasecmp( 'https', $parts['scheme'] )
			|| ! is_string( $parts['host'] ?? null )
			|| '' === $parts['host']
			|| isset( $parts['user'] )
			|| isset( $parts['pass'] )
			|| isset( $parts['query'] )
			|| isset( $parts['fragment'] )
			|| ( isset( $parts['port'] ) && 443 !== $parts['port'] )
			|| ! is_string( $parts['path'] ?? null )
			|| '/' === $parts['path']
			|| ! self::isDnsHost( $parts['host'] )
			|| self::isNumericSpelling( $parts['host'] )
			|| self::hasDotPathSegment( $parts['path'] )
		) {
			throw new InvalidArgumentException( 'charter_cimd_identifier_invalid' );
		}

		return new self( $submitted, $parts['host'] );
	}

	/** Returns the exact client ID, fetch URL, and cache identity. */
	public function exact(): string {
		return $this->exact;
	}

	/** Returns the validated DNS host without changing its spelling. */
	public function host(): string {
		return $this->host;
	}

	/**
	 * Reports whether the host is a bounded ASCII DNS name.
	 *
	 * @param string $host Candidate host.
	 */
	private static function isDnsHost( string $host ): bool {
		if ( 253 < strlen( $host ) || 1 === preg_match( '/[^\x00-\x7f]/', $host ) || false !== filter_var( trim( $host, '[]' ), FILTER_VALIDATE_IP ) ) {
			return false;
		}

		foreach ( explode( '.', rtrim( $host, '.' ) ) as $label ) {
			if ( '' === $label || 63 < strlen( $label ) || 1 !== preg_match( '/\A[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?\z/', $label ) ) {
				return false;
			}
		}

		return true;
	}

	/**
	 * Rejects decimal, octal, hexadecimal, and mixed-radix address spellings.
	 *
	 * @param string $host Candidate host.
	 */
	private static function isNumericSpelling( string $host ): bool {
		return 1 === preg_match( '/\A(?:0[xX][0-9A-Fa-f]+|[0-9]+)(?:\.(?:0[xX][0-9A-Fa-f]+|[0-9]+))*\z/', rtrim( $host, '.' ) );
	}

	/**
	 * Rejects literal or repeatedly encoded single-dot and double-dot segments.
	 *
	 * @param string $path Candidate path.
	 */
	private static function hasDotPathSegment( string $path ): bool {
		foreach ( explode( '/', $path ) as $segment ) {
			$decoded    = $segment;
			$iterations = strlen( $segment );
			for ( $iteration = 0; $iteration <= $iterations; ++$iteration ) {
				$next = rawurldecode( $decoded );
				if ( $next === $decoded ) {
					break;
				}
				$decoded = $next;
			}
			if ( '.' === $decoded || '..' === $decoded ) {
				return true;
			}
		}

		return false;
	}
}
