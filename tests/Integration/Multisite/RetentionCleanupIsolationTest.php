<?php
/**
 * Production OAuth retention isolation on Multisite.
 *
 * @package GalatanOvidiu\Charter
 */

declare(strict_types=1);

namespace GalatanOvidiu\Charter\Tests\Integration\Multisite;

use GalatanOvidiu\Charter\Cli\CleanupCommand;
use GalatanOvidiu\Charter\OAuth\AuthorizationService;
use GalatanOvidiu\Charter\OAuth\CredentialStore;
use GalatanOvidiu\Charter\OAuth\TransactionManager;
use GalatanOvidiu\Charter\Plugin;
use GalatanOvidiu\Charter\Schema;
use mysqli;
use RuntimeException;
use WP_UnitTestCase;

/**
 * Proves site-local tables, status, and sequential network orchestration.
 *
 * @since 0.1.0
 */
final class RetentionCleanupIsolationTest extends WP_UnitTestCase {

	/**
	 * First exact issuer site.
	 *
	 * @var int
	 */
	private static int $firstSiteId;

	/**
	 * Second exact issuer site.
	 *
	 * @var int
	 */
	private static int $secondSiteId;

	/**
	 * Prior network activation record.
	 *
	 * @var array<string, mixed>
	 */
	private array $previousNetworkPlugins = array();

	/**
	 * HTTPS domain-mapping simulation for exact issuer preparation.
	 *
	 * @var \Closure
	 */
	private \Closure $httpsUrlFilter;

	/** Creates two origin-addressed sites and their independent tables. */
	public static function set_up_before_class(): void {
		parent::set_up_before_class();
		self::$firstSiteId  = self::createSite( 'cleanup-one.example.org' );
		self::$secondSiteId = self::createSite( 'cleanup-two.example.org' );
		foreach ( array( self::$firstSiteId, self::$secondSiteId ) as $siteId ) {
			switch_to_blog( $siteId );
			try {
				Schema::install();
			} finally {
				restore_current_blog();
			}
		}
	}

	/** Deletes the exact fixture sites after their tables are unused. */
	public static function tear_down_after_class(): void {
		wp_delete_site( self::$firstSiteId );
		wp_delete_site( self::$secondSiteId );
		parent::tear_down_after_class();
	}

	/** Enables the network control plane and resets both site boundaries. */
	public function set_up(): void {
		parent::set_up();
		$plugins                                    = get_site_option( 'active_sitewide_plugins', array() );
		$this->previousNetworkPlugins               = is_array( $plugins ) ? $plugins : array();
		$plugins                                    = $this->previousNetworkPlugins;
		$plugins[ plugin_basename( CHARTER_FILE ) ] = time();
		update_site_option( 'active_sitewide_plugins', $plugins );
		$this->httpsUrlFilter = static function ( string $url ): string {
			$host = wp_parse_url( $url, PHP_URL_HOST );

			return is_string( $host ) && str_ends_with( $host, '.example.org' )
				? (string) preg_replace( '/^http:/D', 'https:', $url )
				: $url;
		};
		add_filter( 'home_url', $this->httpsUrlFilter );
		add_filter( 'site_url', $this->httpsUrlFilter );

		foreach ( array( self::$firstSiteId, self::$secondSiteId ) as $siteId ) {
			switch_to_blog( $siteId );
			try {
				$plugin = Plugin::boot();
				Schema::install();
				$plugin->credentials()->deleteAll();
				$plugin->clients()->deleteAll();
				$plugin->audit()->deleteAll();
				$plugin->cleanup()->deleteStatus();
				$plugin->siteState()->delete();
				$prepared = $plugin->siteState()->prepareCurrentSite();
				$record   = get_option( 'charter_oauth_site_state', array() );
				$error    = is_array( $record ) && is_string( $record['error'] ?? null ) ? $record['error'] : 'unknown_preparation_error';
				self::assertTrue( $prepared, $error );
				$identity = $plugin->siteState()->identity();
				self::assertNotNull( $identity );
				self::assertTrue( $plugin->siteState()->recordDiscoveryVerification( $identity->issuer() ) );
				self::assertTrue( $plugin->siteState()->enable( $identity->issuer() ) );
			} finally {
				restore_current_blog();
			}
		}
	}

	/** Restores network activation and clears independent site records. */
	public function tear_down(): void {
		remove_filter( 'home_url', $this->httpsUrlFilter );
		remove_filter( 'site_url', $this->httpsUrlFilter );
		foreach ( array( self::$firstSiteId, self::$secondSiteId ) as $siteId ) {
			switch_to_blog( $siteId );
			try {
				Plugin::boot()->credentials()->deleteAll();
				Plugin::boot()->audit()->deleteAll();
				Plugin::boot()->cleanup()->deleteStatus();
				Plugin::boot()->siteState()->delete();
			} finally {
				restore_current_blog();
			}
		}
		update_site_option( 'active_sitewide_plugins', $this->previousNetworkPlugins );
		parent::tear_down();
	}

	/** Verifies cleanup never reaches a sibling and selected jobs remain sequential. */
	public function testSelectedSiteCleanupCannotCrossAMultisiteBoundary(): void {
		$timestamp  = time();
		$originBlog = self::currentBlogId();
		$this->insertCollidingCredentials( self::$firstSiteId, $timestamp );
		$this->insertCollidingCredentials( self::$secondSiteId, $timestamp );
		$plugin  = Plugin::boot();
		$command = new CleanupCommand( $plugin->cleanup(), $plugin->siteState() );

		$firstResult = $command->runForSites( array( self::$firstSiteId ), 100, 1, $timestamp );
		self::assertSame( 1, $firstResult[ self::$firstSiteId ]['deleted'] ?? null );
		self::assertSame( $originBlog, self::currentBlogId() );
		self::assertSame( 0, $this->countCredential( self::$firstSiteId, 900001 ) );
		self::assertSame( 1, $this->countCredential( self::$firstSiteId, 900002 ) );
		self::assertSame( 1, $this->countCredential( self::$secondSiteId, 900001 ) );
		self::assertSame( 1, $this->countCredential( self::$secondSiteId, 900002 ) );
		$status = $command->statusForSites( array( self::$firstSiteId, self::$secondSiteId ), $timestamp );
		self::assertSame( 'current', $status[ self::$firstSiteId ]['state'] ?? null );
		self::assertSame( 'scheduled', $status[ self::$secondSiteId ]['state'] ?? null );

		$networkResult = $command->runForSites( array( self::$secondSiteId, self::$firstSiteId ), 1, 2, $timestamp + 1 );
		self::assertSame( array( self::$secondSiteId, self::$firstSiteId ), array_keys( $networkResult ) );
		self::assertSame( 1, $networkResult[ self::$secondSiteId ]['deleted'] ?? null );
		self::assertSame( 0, $networkResult[ self::$firstSiteId ]['deleted'] ?? null );
		self::assertSame( $originBlog, self::currentBlogId() );
		self::assertSame( 0, $this->countCredential( self::$secondSiteId, 900001 ) );
		self::assertSame( 1, $this->countCredential( self::$secondSiteId, 900002 ) );
	}

	/**
	 * Inserts the same site-local identifiers into one selected site table.
	 *
	 * @param int $siteId WordPress site identifier.
	 * @param int $timestamp Current Unix timestamp.
	 */
	private function insertCollidingCredentials( int $siteId, int $timestamp ): void {
		switch_to_blog( $siteId );
		try {
			$identity = Plugin::boot()->siteState()->identity();
			self::assertNotNull( $identity );
			( new TransactionManager() )->run(
				static function ( mysqli $database ) use ( $identity, $timestamp ): void {
					$table = self::quotedTable( Schema::credentialTable() );
					foreach (
						array(
							900001 => $timestamp - 2 * DAY_IN_SECONDS,
							900002 => $timestamp - 2 * HOUR_IN_SECONDS,
						) as $id => $createdAt
					) {
						$result = $database->execute_query(
							"INSERT INTO {$table}
							(id,credential_type,digest,issuer,resource,client_id,redirect_uri,user_id,scope,code_challenge,request_state,expires_at,consumed_at,created_at,grant_id,parent_id,continuing_access,client_metadata_fingerprint)
							VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
							array( $id, CredentialStore::AUTHORIZATION_REQUEST, hash( 'sha256', $identity->issuer() . ':' . $id ), $identity->issuer(), $identity->issuer(), 'multisite-cleanup-client', 'https://client.example.test/callback', 1, AuthorizationService::GENERAL_SCOPE, '', null, $createdAt, null, $createdAt, null, null, 0, '' )
						); // phpcs:ignore WordPress.DB.RestrictedFunctions.mysql_mysqli -- Test fixture uses the production-owned transaction boundary.
						if ( true !== $result ) {
							throw new RuntimeException( 'charter_multisite_cleanup_fixture_failed' );
						}
					}
				}
			);
		} finally {
			restore_current_blog();
		}
	}

	/**
	 * Counts one colliding site-local credential identifier.
	 *
	 * @param int $siteId WordPress site identifier.
	 * @param int $credentialId Site-local credential identifier.
	 */
	private function countCredential( int $siteId, int $credentialId ): int {
		switch_to_blog( $siteId );
		try {
			return ( new TransactionManager() )->run(
				static function ( mysqli $database ) use ( $credentialId ): int {
					$table  = self::quotedTable( Schema::credentialTable() );
					$result = $database->execute_query( "SELECT COUNT(*) AS credential_count FROM {$table} WHERE id = ?", array( $credentialId ) ); // phpcs:ignore WordPress.DB.RestrictedFunctions.mysql_mysqli,WordPress.DB.PreparedSQL.InterpolatedNotPrepared -- Test-only trusted table with a bound identifier.
					if ( ! $result instanceof \mysqli_result ) {
						throw new RuntimeException( 'charter_multisite_cleanup_count_failed' );
					}
					$row = $result->fetch_assoc();
					$result->free();
					$count = is_array( $row ) ? $row['credential_count'] ?? null : null;

					return is_int( $count ) ? $count : ( is_string( $count ) && ctype_digit( $count ) ? (int) $count : 0 );
				}
			);
		} finally {
			restore_current_blog();
		}
	}

	/**
	 * Creates one supported bare-origin Multisite site.
	 *
	 * @param string $domain Public site domain.
	 */
	private static function createSite( string $domain ): int {
		$siteId = self::factory()->blog->create(
			array(
				'domain' => $domain,
				'path'   => '/',
			)
		);
		update_blog_option( $siteId, 'home', 'https://' . $domain );
		update_blog_option( $siteId, 'siteurl', 'https://' . $domain );

		return $siteId;
	}

	/** Returns WordPress's current non-identity blog locator. */
	private static function currentBlogId(): int {
		global $wpdb;

		if ( ! $wpdb instanceof \wpdb ) {
			return 0;
		}
		$siteId = $wpdb->blogid;

		return is_int( $siteId ) ? $siteId : ( is_string( $siteId ) && ctype_digit( $siteId ) ? (int) $siteId : 0 );
	}

	/**
	 * Quotes one trusted WordPress-derived table identifier.
	 *
	 * @param string $table Table identifier.
	 * @throws RuntimeException When the identifier is invalid.
	 */
	private static function quotedTable( string $table ): string {
		if ( 1 !== preg_match( '/^[A-Za-z0-9_]+$/D', $table ) ) {
			throw new RuntimeException( 'charter_multisite_cleanup_table_invalid' );
		}

		return '`' . $table . '`';
	}
}
