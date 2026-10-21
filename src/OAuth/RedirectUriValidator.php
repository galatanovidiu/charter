<?php
/**
 * OAuth redirect URI validation.
 *
 * @package GalatanOvidiu\Charter
 */

declare(strict_types=1);

namespace GalatanOvidiu\Charter\OAuth;

/**
 * Applies the exact production redirect classes shared by every onboarding path.
 *
 * @since 0.1.0
 */
final class RedirectUriValidator {

	/**
	 * Reports whether one redirect URI is accepted by the v1 production policy.
	 *
	 * @since 0.1.0
	 *
	 * @param string $uri Candidate redirect URI.
	 */
	public static function isValid( string $uri ): bool {
		if (
			'' === $uri
			|| 2048 < strlen( $uri )
			|| 1 === preg_match( '/[^\x21-\x7e]/', $uri )
			|| str_contains( $uri, '\\' )
			|| 1 === preg_match( '/%(?![0-9A-Fa-f]{2})/', $uri )
		) {
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
			|| ! self::isValidHost( $parts['host'] )
			|| ( isset( $parts['port'] ) && 1 > $parts['port'] )
		) {
			return false;
		}

		$scheme = strtolower( $parts['scheme'] );
		$host   = strtolower( $parts['host'] );
		if ( 'https' === $scheme ) {
			return true;
		}

		return 'http' === $scheme
			&& in_array( $host, array( 'localhost', '127.0.0.1', '::1', '[::1]' ), true );
	}

	/**
	 * Reports whether one accepted callback uses a device-local loopback host.
	 *
	 * @param string $uri Validated redirect URI.
	 */
	public static function isLoopback( string $uri ): bool {
		$parts = wp_parse_url( $uri );

		return false !== $parts
			&& 'http' === strtolower( (string) ( $parts['scheme'] ?? '' ) )
			&& in_array( strtolower( (string) ( $parts['host'] ?? '' ) ), array( 'localhost', '127.0.0.1', '::1', '[::1]' ), true );
	}

	/**
	 * Rejects ambiguous or malformed DNS and address spellings.
	 *
	 * @param string $host Parsed URI host.
	 */
	private static function isValidHost( string $host ): bool {
		$address = trim( $host, '[]' );
		if ( false !== filter_var( $address, FILTER_VALIDATE_IP ) ) {
			return $host === $address || '[' . $address . ']' === $host;
		}

		if ( 253 < strlen( $host ) || 1 === preg_match( '/[^\x00-\x7f]/', $host ) ) {
			return false;
		}

		foreach ( explode( '.', rtrim( $host, '.' ) ) as $label ) {
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
	 * This class contains static validation only.
	 */
	private function __construct() {
	}
}
