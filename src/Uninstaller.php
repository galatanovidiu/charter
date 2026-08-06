<?php
/**
 * Irreversible Charter uninstall cleanup.
 *
 * @package GalatanOvidiu\Charter
 */

declare(strict_types=1);

namespace GalatanOvidiu\Charter;

use GalatanOvidiu\Charter\OAuth\ClientCleanup;
use GalatanOvidiu\Charter\Site\SiteOrchestrator;

/** Purges every site-local Charter record without booting OAuth services. */
final class Uninstaller {
	private const REWRITE_RULES = array(
		'^\.well-known/oauth-authorization-server/?$'  => 'index.php?rest_route=/charter/v1/metadata/authorization-server',
		'^\.well-known/oauth-protected-resource/?$'    => 'index.php?rest_route=/charter/v1/metadata/protected-resource',
		'^\.well-known/oauth-protected-resource/(.+)$' => 'index.php?rest_route=/charter/v1/metadata/protected-resource/$matches[1]',
	);

	private const OPTIONS = array(
		'charter_oauth_schema_version',
		'charter_oauth_site_state',
		'charter_oauth_clients',
		'charter_oauth_clients_migrated',
		'charter_oauth_dcr_enabled',
		'charter_oauth_emergency_mode',
		'charter_oauth_cleanup_status',
		'charter_oauth_cleanup_first_scheduled_at',
		'charter_oauth_last_cleanup_at',
		'charter_oauth_signing_key_guard',
	);

	/** Permanently removes Charter data from every WordPress site. */
	public static function uninstall(): void {
		if ( ! is_multisite() ) {
			self::purgeSite( SiteOrchestrator::currentSiteId() );

			return;
		}

		$offset    = 0;
		$siteCount = 0;
		do {
			$siteIds = get_sites(
				array(
					'fields' => 'ids',
					'number' => 100,
					'offset' => $offset,
				)
			);
			foreach ( $siteIds as $siteId ) {
				self::purgeSite( $siteId );
			}
			$siteCount = count( $siteIds );
			$offset   += $siteCount;
		} while ( 100 === $siteCount );
	}

	/**
	 * Permanently removes Charter data from one exact site.
	 *
	 * @param int $siteId WordPress site identifier.
	 */
	public static function purgeSite( int $siteId ): void {
		$switched = SiteOrchestrator::currentSiteId() !== $siteId;
		if ( $switched ) {
			switch_to_blog( $siteId );
		}

		try {
			wp_clear_scheduled_hook( ClientCleanup::HOOK );
			wp_clear_scheduled_hook( ClientCleanup::HOOK, array( 'daily' ) );
			wp_clear_scheduled_hook( ClientCleanup::HOOK, array( 'continuation' ) );

			foreach ( self::OPTIONS as $option ) {
				delete_option( $option );
			}
			self::removeRewriteRulesForCurrentSite();

			Schema::deleteUserMetadataForSite( $siteId );
			Schema::dropTablesForSite( $siteId );
		} finally {
			if ( $switched ) {
				restore_current_blog();
			}
		}
	}

	/**
	 * Removes only Charter's persisted well-known rewrite rules.
	 *
	 * @internal Exposed for exact lifecycle verification.
	 */
	public static function removeRewriteRulesForCurrentSite(): void {
		$rules = get_option( 'rewrite_rules', array() );
		if ( ! is_array( $rules ) ) {
			return;
		}

		$changed = false;
		foreach ( self::REWRITE_RULES as $pattern => $target ) {
			if ( ( $rules[ $pattern ] ?? null ) !== $target ) {
				continue;
			}

			unset( $rules[ $pattern ] );
			$changed = true;
		}

		if ( $changed ) {
			update_option( 'rewrite_rules', $rules );
		}
	}

	/** This class contains static irreversible cleanup only. */
	private function __construct() {
	}
}
