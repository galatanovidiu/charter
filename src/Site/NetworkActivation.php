<?php
/**
 * Multisite network-activation boundary.
 *
 * @package GalatanOvidiu\Charter
 */

declare(strict_types=1);

namespace GalatanOvidiu\Charter\Site;

/**
 * Reports whether Charter is active for the complete current network.
 *
 * @since 0.1.0
 */
final class NetworkActivation {

	/**
	 * Reports whether the cross-site control plane may exist.
	 *
	 * @since 0.1.0
	 */
	public static function isActive(): bool {
		if ( ! is_multisite() ) {
			return false;
		}

		$plugins = get_site_option( 'active_sitewide_plugins', array() );

		return is_array( $plugins ) && isset( $plugins[ plugin_basename( CHARTER_FILE ) ] );
	}

	/** This class contains static activation checks only. */
	private function __construct() {
	}
}
