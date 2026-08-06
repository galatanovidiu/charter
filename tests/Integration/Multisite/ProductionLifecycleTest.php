<?php
/**
 * Production Multisite activation and deletion lifecycle tests.
 *
 * @package GalatanOvidiu\Charter
 */

declare(strict_types=1);

namespace GalatanOvidiu\Charter\Tests\Integration\Multisite;

use GalatanOvidiu\Charter\Plugin;
use GalatanOvidiu\Charter\Schema;
use GalatanOvidiu\Charter\Site\SiteState;
use WP_Site;
use WP_UnitTestCase;

/** Verifies the approved network-active Multisite product boundary. */
final class ProductionLifecycleTest extends WP_UnitTestCase {

	/** Per-site activation cannot initialize OAuth authority on Multisite. */
	public function testPerSiteActivationLeavesSiteAvailableWithoutStorage(): void {
		$networkPlugins = get_site_option( 'active_sitewide_plugins', array() );
		$siteId         = self::createSite( 'per-site-inactive.example.org' );
		$withoutCharter = is_array( $networkPlugins ) ? $networkPlugins : array();
		unset( $withoutCharter[ plugin_basename( CHARTER_FILE ) ] );
		update_site_option( 'active_sitewide_plugins', $withoutCharter );

		switch_to_blog( $siteId );
		try {
			Plugin::activate( false );

			self::assertFalse( Schema::isInstalled() );
			self::assertSame( SiteState::AVAILABLE, Plugin::boot()->siteState()->state() );
			self::assertNull( Plugin::boot()->siteState()->identity() );
			foreach ( Schema::tablesForSite( $siteId ) as $table ) {
				self::assertFalse( self::tableExists( $table ) );
			}
		} finally {
			restore_current_blog();
			update_site_option( 'active_sitewide_plugins', $networkPlugins );
			wp_delete_site( $siteId );
		}
	}

	/** Selected network-active issuers receive schema upgrades on ordinary load. */
	public function testSelectedIssuerReceivesSchemaUpgradeAfterPluginUpdate(): void {
		$siteId = self::createSite( 'upgrade-production.example.org' );

		switch_to_blog( $siteId );
		try {
			update_option( 'home', 'http://example.org' );
			update_option( 'siteurl', 'http://example.org' );
			Schema::install();
			self::assertTrue(
				Plugin::boot()->siteState()->prepareCurrentSite(),
				wp_json_encode( get_option( 'charter_oauth_site_state' ) )
			);
			delete_option( 'charter_oauth_schema_version' );
			self::assertFalse( Schema::isInstalled() );

			Plugin::boot()->ensureCurrentSiteReady();

			self::assertTrue( Schema::isInstalled() );
			self::assertSame( SiteState::PREPARED, Plugin::boot()->siteState()->state() );
		} finally {
			restore_current_blog();
			wp_delete_site( $siteId );
		}
	}

	/** Permanent site deletion selects only target tables and user metadata. */
	public function testSiteDeletionSelectsOnlyTargetTablesAndUserMetadata(): void {
		$targetId  = self::createSite( 'deleted-production.example.org' );
		$siblingId = self::createSite( 'retained-production.example.org' );
		$userId    = self::factory()->user->create();

		$targetTables   = Schema::tablesForSite( $targetId );
		$siblingTables  = Schema::tablesForSite( $siblingId );
		$targetMetaKey  = $GLOBALS['wpdb']->get_blog_prefix( $targetId ) . 'charter_oauth_revocation_notice_cursor';
		$siblingMetaKey = $GLOBALS['wpdb']->get_blog_prefix( $siblingId ) . 'charter_oauth_revocation_notice_cursor';
		foreach ( array( $targetId, $siblingId ) as $siteId ) {
			switch_to_blog( $siteId );
			try {
				update_user_option( $userId, 'charter_oauth_revocation_notice_cursor', array( 'grant_id' => 1 ) );
			} finally {
				restore_current_blog();
			}
		}

		$selectedTables = Schema::addSiteTablesToDrop( array( $GLOBALS['wpdb']->get_blog_prefix( $targetId ) . 'posts' ), $targetId );
		$result         = wp_delete_site( $targetId );

		self::assertInstanceOf( WP_Site::class, $result );
		self::assertNull( get_site( $targetId ) );
		self::assertSame( 0, self::userMetaCount( $targetMetaKey ) );
		foreach ( $targetTables as $table ) {
			self::assertContains( $table, $selectedTables );
		}

		self::assertInstanceOf( WP_Site::class, get_site( $siblingId ) );
		self::assertSame( 1, self::userMetaCount( $siblingMetaKey ) );
		foreach ( $siblingTables as $table ) {
			self::assertNotContains( $table, $selectedTables );
		}

		wp_delete_site( $siblingId );
	}

	/**
	 * Creates one origin-addressed WordPress site.
	 *
	 * @param string $domain Site domain.
	 */
	private static function createSite( string $domain ): int {
		return self::factory()->blog->create(
			array(
				'domain' => $domain,
				'path'   => '/',
			)
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

	/**
	 * Counts one exact user option without reading its value.
	 *
	 * @param string $metaKey Exact user metadata key.
	 */
	private static function userMetaCount( string $metaKey ): int {
		global $wpdb;

		return (int) $wpdb->get_var( $wpdb->prepare( "SELECT COUNT(*) FROM {$wpdb->usermeta} WHERE meta_key = %s", $metaKey ) ); // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching,WordPress.DB.PreparedSQL.InterpolatedNotPrepared -- Exact non-secret lifecycle assertion.
	}
}
