<?php
/**
 * Disposable Slice 0 WordPress site-deletion lifecycle adapter.
 *
 * @package GalatanOvidiu\Charter
 */

declare(strict_types=1);

namespace GalatanOvidiu\Charter\Tests\Prototype\Multisite;

use WP_Site;

/**
 * Connects proof cleanup to WordPress's permanent site-deletion hook.
 *
 * @since 0.1.0
 */
final class SiteDeletionLifecycle {

	/**
	 * Registers the disposable deletion callback when it is not present.
	 *
	 * @since 0.1.0
	 */
	public static function register(): void {
		if ( false !== has_action( 'wp_delete_site', array( self::class, 'deleteSite' ) ) ) {
			return;
		}

		add_action( 'wp_delete_site', array( self::class, 'deleteSite' ) );
	}

	/**
	 * Removes proof authority located by the permanently deleted site.
	 *
	 * @since 0.1.0
	 *
	 * @param WP_Site $deletedSite The deleted WordPress site object.
	 */
	public static function deleteSite( WP_Site $deletedSite ): void {
		$siteId = (int) $deletedSite->blog_id;

		SiteIssuerLifecycle::deleteForSite( $siteId );
		ProofCredentialStore::deleteForSite( $siteId );
	}
}
