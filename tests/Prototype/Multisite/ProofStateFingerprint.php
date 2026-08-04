<?php
/**
 * Disposable Slice 0 proof-state fingerprint helper.
 *
 * @package GalatanOvidiu\Charter
 */

declare(strict_types=1);

namespace GalatanOvidiu\Charter\Tests\Prototype\Multisite;

/**
 * Produces opaque fingerprints for byte-for-byte network-option comparisons.
 *
 * @since 0.1.0
 */
final class ProofStateFingerprint {

	/**
	 * Fingerprints one disposable network option without exposing its value.
	 *
	 * @since 0.1.0
	 *
	 * @param string $optionName Network option name.
	 * @return string The opaque state fingerprint.
	 */
	public static function forNetworkOption( string $optionName ): string {
		$encodedState = wp_json_encode( get_network_option( null, $optionName, array() ) );

		return hash( 'sha256', is_string( $encodedState ) ? $encodedState : '' );
	}
}
