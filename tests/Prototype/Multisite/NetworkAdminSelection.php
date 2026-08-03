<?php
/**
 * Disposable Slice 0 Network Admin selection command.
 *
 * @package GalatanOvidiu\Charter
 */

declare(strict_types=1);

namespace GalatanOvidiu\Charter\Tests\Prototype\Multisite;

/**
 * Prepares one explicitly selected site issuer for the network control plane.
 *
 * @since 0.1.0
 */
final class NetworkAdminSelection {

	/**
	 * Prepares one selected WordPress site through the shared lifecycle operation.
	 *
	 * @since 0.1.0
	 *
	 * @param int $siteId The selected WordPress site locator.
	 */
	public static function prepareSite( int $siteId ): void {
		SiteIssuerLifecycle::prepare( IssuerIdentity::forSite( $siteId ) );
	}
}
