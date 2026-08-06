<?php
/**
 * Single-site deactivation and uninstall integration tests.
 *
 * @package GalatanOvidiu\Charter
 */

declare(strict_types=1);

namespace GalatanOvidiu\Charter\Tests\Integration;

use GalatanOvidiu\Charter\Plugin;
use GalatanOvidiu\Charter\Schema;
use GalatanOvidiu\Charter\Uninstaller;
use WP_UnitTestCase;

/** Verifies the irreversible boundary between deactivation and uninstall. */
final class UninstallLifecycleTest extends WP_UnitTestCase {

	/** Restores the current site's production schema for following tests. */
	public function tearDown(): void {
		Schema::install();
		Plugin::boot()->siteState()->prepareCurrentSite();

		parent::tearDown();
	}

	/** Deactivation retains complete Charter state. */
	public function testDeactivationRetainsOAuthState(): void {
		require_once ABSPATH . 'wp-admin/includes/plugin.php';

		Schema::install();
		Plugin::boot()->siteState()->prepareCurrentSite();
		update_option( 'charter_oauth_dcr_enabled', '0', false );
		$activePlugins = (array) get_option( 'active_plugins', array() );
		$plugin        = plugin_basename( CHARTER_FILE );
		if ( ! in_array( $plugin, $activePlugins, true ) ) {
			$activePlugins[] = $plugin;
			update_option( 'active_plugins', $activePlugins );
		}

		deactivate_plugins( $plugin, true, false );

		self::assertTrue( Schema::isInstalled() );
		self::assertSame( '0', get_option( 'charter_oauth_dcr_enabled' ) );
		self::assertNotNull( Plugin::boot()->siteState()->identity() );
		foreach ( Schema::tablesForSite( get_current_blog_id() ) as $table ) {
			self::assertTrue( self::tableExists( $table ) );
		}
	}

	/** Site-table ownership lists every and only Charter table. */
	public function testSiteTableOwnershipIsExact(): void {
		$prefix = $GLOBALS['wpdb']->get_blog_prefix();

		self::assertSame(
			array(
				$prefix . 'charter_oauth_credentials',
				$prefix . 'charter_oauth_grants',
				$prefix . 'charter_oauth_clients',
				$prefix . 'charter_oauth_rate_limits',
				$prefix . 'charter_oauth_audit',
				$prefix . 'charter_oauth_cimd_cache',
			),
			Schema::tablesForSite( get_current_blog_id() )
		);
	}

	/** Uninstall removes only Charter's persisted well-known rewrite rules. */
	public function testUninstallRemovesCharterRewriteRulesOnly(): void {
		update_option(
			'rewrite_rules',
			array(
				'^unrelated/?$' => 'index.php?unrelated=1',
				'^\.well-known/oauth-authorization-server/?$' => 'index.php?rest_route=/charter/v1/metadata/authorization-server',
				'^\.well-known/oauth-protected-resource/?$' => 'index.php?rest_route=/charter/v1/metadata/protected-resource',
				'^\.well-known/oauth-protected-resource/(.+)$' => 'index.php?rest_route=/charter/v1/metadata/protected-resource/$matches[1]',
			)
		);

		Uninstaller::removeRewriteRulesForCurrentSite();

		self::assertSame(
			array( '^unrelated/?$' => 'index.php?unrelated=1' ),
			get_option( 'rewrite_rules' )
		);
	}

	/**
	 * Reports whether one exact database table exists.
	 *
	 * @param string $table Exact database table name.
	 */
	private static function tableExists( string $table ): bool {
		global $wpdb;

		return $table === $wpdb->get_var( $wpdb->prepare( 'SHOW TABLES LIKE %s', $wpdb->esc_like( $table ) ) ); // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching -- Exact schema lifecycle assertion.
	}
}
