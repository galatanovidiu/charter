<?php
/**
 * Disposable Slice 0 WordPress activation lifecycle adapter.
 *
 * @package GalatanOvidiu\Charter
 */

declare(strict_types=1);

namespace GalatanOvidiu\Charter\Tests\Prototype\Multisite;

/**
 * Connects the proof lifecycle to WordPress's real activation hook.
 *
 * @since 0.1.0
 */
final class ActivationLifecycle {
	/**
	 * Registers the disposable activation callback when it is not present.
	 *
	 * @since 0.1.0
	 *
	 * @param string $pluginFile The Charter plugin entry file.
	 */
	public static function register( string $pluginFile ): void {
		$hookName = 'activate_' . plugin_basename( $pluginFile );

		if ( false !== has_action( $hookName, array( self::class, 'activate' ) ) ) {
			return;
		}

		register_activation_hook( $pluginFile, array( self::class, 'activate' ) );
	}

	/**
	 * Observes WordPress activation without preparing network-active sites.
	 *
	 * @since 0.1.0
	 *
	 * @param bool $networkWide Whether WordPress is activating network-wide.
	 */
	public static function activate( bool $networkWide ): void {
		if ( $networkWide ) {
			return;
		}

		SiteIssuerLifecycle::prepare( IssuerIdentity::forCurrentSite() );
	}
}
