<?php
/**
 * Exact disposable CIMD Client Identifier value.
 *
 * @package GalatanOvidiu\Charter
 */

declare(strict_types=1);

namespace GalatanOvidiu\Charter\Tests\Prototype\CimdOutboundSafety;

use InvalidArgumentException;

/**
 * Preserves the submitted Client Identifier while validating its fetch shape.
 *
 * @since 0.1.0
 */
final class ClientIdentifier {

	/**
	 * Exact submitted identifier.
	 *
	 * @since 0.1.0
	 *
	 * @var string
	 */
	private string $exact;

	/**
	 * Parsed DNS host, preserved as submitted.
	 *
	 * @since 0.1.0
	 *
	 * @var string
	 */
	private string $host;

	/**
	 * Creates an already-validated value.
	 *
	 * @since 0.1.0
	 *
	 * @param string $exact Exact submitted identifier.
	 * @param string $host  Parsed DNS host.
	 */
	private function __construct( string $exact, string $host ) {
		$this->exact = $exact;
		$this->host  = $host;
	}

	/**
	 * Validates one exact Client Identifier without normalizing its identity.
	 *
	 * @since 0.1.0
	 *
	 * @param string $submitted Submitted Client Identifier.
	 * @return self Validated identifier.
	 * @throws InvalidArgumentException When the submitted URL violates the proof profile.
	 */
	public static function fromString( string $submitted ): self {
		if (
			'' === $submitted
			|| 2048 < strlen( $submitted )
			|| 1 === preg_match( '/[\x00-\x20\x7f]/', $submitted )
			|| str_contains( $submitted, '\\' )
			|| 1 === preg_match( '/%(?![0-9A-Fa-f]{2})/', $submitted )
		) {
			throw new InvalidArgumentException( 'The Client Identifier URL is invalid.' );
		}

		// phpcs:ignore WordPress.WP.AlternativeFunctions.parse_url_parse_url -- Standalone proof value does not bootstrap WordPress.
		$parts = parse_url( $submitted );

		if (
			! is_array( $parts )
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
		) {
			throw new InvalidArgumentException( 'The Client Identifier URL is invalid.' );
		}

		$host = $parts['host'];

		if (
			! self::isValidDnsHost( $host )
			|| self::isNumericAddressSpelling( $host )
			|| self::hasDotPathSegment( $parts['path'] )
		) {
			throw new InvalidArgumentException( 'The Client Identifier URL is invalid.' );
		}

		return new self( $submitted, $host );
	}

	/**
	 * Rejects non-canonical numeric IPv4 spellings before any resolver can
	 * interpret them as decimal, octal, hexadecimal, or mixed-radix literals.
	 *
	 * @param string $host Parsed host.
	 * @return bool Whether the host is a numeric address spelling.
	 */
	private static function isNumericAddressSpelling( string $host ): bool {
		return 1 === preg_match(
			'/\A(?:0[xX][0-9A-Fa-f]+|[0-9]+)(?:\.(?:0[xX][0-9A-Fa-f]+|[0-9]+))*\z/',
			rtrim( $host, '.' )
		);
	}

	/**
	 * Returns the exact submitted identity.
	 *
	 * @since 0.1.0
	 *
	 * @return string Exact identifier.
	 */
	public function exact(): string {
		return $this->exact;
	}

	/**
	 * Returns the exact fetch URL.
	 *
	 * @since 0.1.0
	 *
	 * @return string Exact fetch URL.
	 */
	public function fetchUrl(): string {
		return $this->exact;
	}

	/**
	 * Returns the exact cache identity.
	 *
	 * @since 0.1.0
	 *
	 * @return string Exact cache key.
	 */
	public function cacheKey(): string {
		return $this->exact;
	}

	/**
	 * Returns the parsed DNS host without changing its spelling.
	 *
	 * @since 0.1.0
	 *
	 * @return string DNS host.
	 */
	public function host(): string {
		return $this->host;
	}

	/**
	 * Returns the only accepted effective destination port.
	 *
	 * @since 0.1.0
	 *
	 * @return int Effective port.
	 */
	public function effectivePort(): int {
		return 443;
	}

	/**
	 * Validates a DNS name without accepting IP literals or raw Unicode.
	 *
	 * @param string $host Parsed host.
	 * @return bool Whether the host is an accepted DNS name.
	 */
	private static function isValidDnsHost( string $host ): bool {
		if (
			253 < strlen( $host )
			|| 1 === preg_match( '/[^\x00-\x7f]/', $host )
			|| false !== filter_var( trim( $host, '[]' ), FILTER_VALIDATE_IP )
		) {
			return false;
		}

		$labels = explode( '.', rtrim( $host, '.' ) );

		foreach ( $labels as $label ) {
			if (
				'' === $label
				|| 63 < strlen( $label )
				|| 1 !== preg_match( '/\A[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?\z/', $label )
			) {
				return false;
			}
		}

		return true;
	}

	/**
	 * Detects literal or encoded single-dot and double-dot path components.
	 *
	 * @param string $path Parsed path.
	 * @return bool Whether a forbidden component is present.
	 */
	private static function hasDotPathSegment( string $path ): bool {
		foreach ( explode( '/', $path ) as $segment ) {
			$decoded = $segment;

			$maximumDecodes = strlen( $segment ) + 1;
			for ( $iteration = 0; $iteration < $maximumDecodes; ++$iteration ) {
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
