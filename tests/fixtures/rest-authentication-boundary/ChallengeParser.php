<?php
/**
 * Minimal Bearer challenge parser for the disposable Slice 0 P2 workers.
 *
 * @package GalatanOvidiu\Charter
 */

declare(strict_types=1);

namespace GalatanOvidiu\Charter\Tests\Fixtures\RestAuthenticationBoundary;

/**
 * Parses fixed proof challenges without making parameter order contractual.
 */
final class ChallengeParser {

	/**
	 * Parses a Bearer challenge into its parameter map.
	 *
	 * @param string $challenge Header value.
	 * @return array<string, string>|null
	 */
	public static function parse( string $challenge ): ?array {
		if ( 1 !== preg_match( '/\ABearer(?:\s+(.+))?\z/D', trim( $challenge ), $matches ) ) {
			return null;
		}

		if ( ! isset( $matches[1] ) || '' === $matches[1] ) {
			return array();
		}

		$parameters = array();
		$remaining  = $matches[1];

		while ( '' !== $remaining ) {
			if ( 1 !== preg_match( '/\A([A-Za-z][A-Za-z0-9_-]*)="((?:\\\\.|[^"\\\\])*)"(?:,\s*|\z)/', $remaining, $part ) ) {
				return null;
			}

			if ( array_key_exists( $part[1], $parameters ) ) {
				return null;
			}

			$parameters[ $part[1] ] = stripcslashes( $part[2] );
			$remaining              = substr( $remaining, strlen( $part[0] ) );
		}

		ksort( $parameters );

		return $parameters;
	}

	/**
	 * Checks an exact challenge independent of parameter order.
	 *
	 * @param string                $challenge Header value.
	 * @param array<string, string> $expected  Expected parameters.
	 */
	public static function isExact( string $challenge, array $expected ): bool {
		ksort( $expected );

		return self::parse( $challenge ) === $expected;
	}

	/**
	 * Prevents construction.
	 */
	private function __construct() {}
}
