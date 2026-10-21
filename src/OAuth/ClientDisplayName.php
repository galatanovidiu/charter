<?php
/**
 * OAuth client display-name safety.
 *
 * @package GalatanOvidiu\Charter
 */

declare(strict_types=1);

namespace GalatanOvidiu\Charter\OAuth;

/** Normalizes display names while rejecting characters that can spoof consent. */
final class ClientDisplayName {

	/**
	 * Returns a safe bounded display name or null.
	 *
	 * @param string $name Candidate client name.
	 */
	public static function normalize( string $name ): ?string {
		if ( '' === $name || 256 < strlen( $name ) || 1 !== preg_match( '//u', $name ) ) {
			return null;
		}

		$unsafe = preg_match( '/[\p{C}\p{Zl}\p{Zp}]/u', $name );
		if ( 0 !== $unsafe ) {
			return null;
		}

		$name    = trim( $name );
		$visible = preg_match( '/[\p{L}\p{N}]/u', $name );

		return '' !== $name && 1 === $visible ? $name : null;
	}

	/** This class contains static validation only. */
	private function __construct() {
	}
}
