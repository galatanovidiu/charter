<?php
/**
 * Slice 0 path-based Multisite HTTP diagnostics.
 *
 * @package GalatanOvidiu\Charter
 */

declare(strict_types=1);

namespace GalatanOvidiu\Charter\Tests\Integration\DiscoveryPublication;

use GalatanOvidiu\Charter\Tests\Prototype\DiscoveryPublication\UnsupportedTopologyDiagnostics;
use GalatanOvidiu\Charter\Tests\Prototype\Multisite\ActivationLifecycle;
use GalatanOvidiu\Charter\Tests\Prototype\Multisite\SiteIssuerLifecycle;
use WP_Site;
use WP_UnitTest_Factory;
use WP_UnitTestCase;

/**
 * Proves WordPress selects the correct path site before Charter's proof seam.
 *
 * @since 0.1.0
 */
final class UnsupportedPathMultisiteHttpTest extends WP_UnitTestCase {

	/**
	 * Internal wp-env web-container origin.
	 *
	 * @var string
	 */
	private const HTTP_ORIGIN = 'http://wordpress';

	/**
	 * Shared public authority for the path pair.
	 *
	 * @var string
	 */
	private const PUBLIC_HOST = 'path-network.charter.test';

	/**
	 * Main-site locator.
	 *
	 * @var int
	 */
	private static int $mainSiteId;

	/**
	 * Path-subsite locator.
	 *
	 * @var int
	 */
	private static int $pathSiteId;

	/**
	 * Creates the committed main/path pair used by the independent web process.
	 *
	 * @since 0.1.0
	 *
	 * @param WP_UnitTest_Factory $factory WordPress test factory.
	 */
	public static function wpSetUpBeforeClass( WP_UnitTest_Factory $factory ): void {
		self::$mainSiteId = $factory->blog->create(
			array(
				'domain' => self::PUBLIC_HOST,
				'path'   => '/',
			)
		);
		self::$pathSiteId = $factory->blog->create(
			array(
				'domain' => self::PUBLIC_HOST,
				'path'   => '/team/',
			)
		);

		update_blog_option( self::$mainSiteId, 'home', 'https://' . self::PUBLIC_HOST );
		update_blog_option( self::$mainSiteId, 'siteurl', 'https://' . self::PUBLIC_HOST );
		update_blog_option( self::$pathSiteId, 'home', 'https://' . self::PUBLIC_HOST . '/team' );
		update_blog_option( self::$pathSiteId, 'siteurl', 'https://' . self::PUBLIC_HOST . '/team' );
	}

	/**
	 * Removes the committed pair and proof state.
	 *
	 * @since 0.1.0
	 */
	public static function wpTearDownAfterClass(): void {
		require_once ABSPATH . 'wp-admin/includes/ms.php';

		SiteIssuerLifecycle::resetProof();

		foreach ( array( self::$pathSiteId, self::$mainSiteId ) as $siteId ) {
			if ( get_site( $siteId ) instanceof WP_Site ) {
				wpmu_delete_blog( $siteId, true );
			}
		}
	}

	/**
	 * Registers proof callbacks and resets activation/state.
	 *
	 * @since 0.1.0
	 */
	public function setUp(): void {
		parent::setUp();

		require_once ABSPATH . 'wp-admin/includes/plugin.php';

		ActivationLifecycle::register( CHARTER_FILE );
		UnsupportedTopologyDiagnostics::register();
		SiteIssuerLifecycle::resetProof();

		foreach ( array( self::$mainSiteId, self::$pathSiteId ) as $siteId ) {
			switch_to_blog( $siteId );
			deactivate_plugins( plugin_basename( CHARTER_FILE ), true, false );
			restore_current_blog();
		}
	}

	/**
	 * Verifies exact site selection and fail-closed path-site behavior over HTTP.
	 *
	 * @since 0.1.0
	 */
	public function testMainSitePublishesWhilePathSubsiteRemainsOperationalAndNonCharter(): void {
		$mainIssuer = 'https://' . self::PUBLIC_HOST;
		$pathIssuer = $mainIssuer . '/team';

		self::activateSite( self::$mainSiteId );
		self::activateSite( self::$pathSiteId );
		update_blog_option( self::$mainSiteId, 'home', 'https://changed-home.charter.test' );
		update_blog_option( self::$mainSiteId, 'siteurl', 'https://changed-siteurl.charter.test' );
		self::commit_transaction();

		$mainDiscovery = self::request( '/.well-known/oauth-authorization-server' );

		self::assertNotWPError( $mainDiscovery );
		self::assertSame( 200, wp_remote_retrieve_response_code( $mainDiscovery ) );
		self::assertSame(
			array( 'issuer' => $mainIssuer ),
			json_decode( wp_remote_retrieve_body( $mainDiscovery ), true, 512, JSON_THROW_ON_ERROR )
		);

		foreach (
			array(
				array( '/.well-known/oauth-authorization-server', 'attacker.invalid' ),
				array( '/.well-known/oauth-authorization-server', self::PUBLIC_HOST . ':8443' ),
				array( '/missing/.well-known/oauth-authorization-server', self::PUBLIC_HOST ),
			) as $hostileRequest
		) {
			$response = self::request( $hostileRequest[0], $hostileRequest[1] );

			self::assertNotWPError( $response );
			self::assertNotSame( 200, wp_remote_retrieve_response_code( $response ) );
			self::assertStringNotContainsString( '"issuer"', wp_remote_retrieve_body( $response ) );
			self::assertStringNotContainsString( '"resource"', wp_remote_retrieve_body( $response ) );
		}

		foreach (
			array(
				'/team/.well-known/oauth-authorization-server',
				'/team/.well-known/oauth-protected-resource',
				'/team/.well-known/oauth-protected-resource/integrations/example',
				'/team/charter-slice0-operation-probe',
			) as $path
		) {
			$response = self::request( $path );

			self::assertNotWPError( $response );
			self::assertNotSame( 200, wp_remote_retrieve_response_code( $response ) );
			self::assertStringNotContainsString( '"issuer"', wp_remote_retrieve_body( $response ) );
			self::assertStringNotContainsString( '"resource"', wp_remote_retrieve_body( $response ) );
		}

		$normalWordPressResponse = self::request( '/team/' );

		self::assertNotWPError( $normalWordPressResponse );
		self::assertLessThan( 500, wp_remote_retrieve_response_code( $normalWordPressResponse ) );

		switch_to_blog( self::$pathSiteId );
		self::assertTrue( is_plugin_active( plugin_basename( CHARTER_FILE ) ) );
		self::assertSame( SiteIssuerLifecycle::PREPARED, SiteIssuerLifecycle::stateFor( $pathIssuer ) );

		ob_start();
		// phpcs:ignore WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedHooknameFound -- Invokes the WordPress core hook to prove the registered surface.
		do_action( 'admin_notices' );
		$administratorNotice = (string) ob_get_clean();
		// phpcs:ignore WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedHooknameFound -- Invokes the WordPress core filter to prove the registered surface.
		$siteHealthTests = apply_filters( 'site_status_tests', array() );
		$siteHealth      = call_user_func( $siteHealthTests['direct']['charter_unsupported_path_topology']['test'] );
		$diagnostics     = UnsupportedTopologyDiagnostics::forCanonicalBase( $pathIssuer );

		restore_current_blog();

		self::assertSame( $diagnostics['administrator_notice'], $administratorNotice );
		self::assertSame( 'critical', $siteHealth['status'] );
		self::assertSame( $diagnostics['message'], $siteHealth['description'] );
		self::assertSame( $diagnostics['message'], $diagnostics['wp_cli']['message'] );
	}

	/**
	 * Activates Charter on one exact site.
	 *
	 * @since 0.1.0
	 *
	 * @param int $siteId Site locator.
	 */
	private static function activateSite( int $siteId ): void {
		switch_to_blog( $siteId );
		$activationResult = activate_plugin( plugin_basename( CHARTER_FILE ) );
		restore_current_blog();

		self::assertNull( $activationResult );
	}

	/**
	 * Performs a real HTTP request with the path-pair public authority.
	 *
	 * @since 0.1.0
	 *
	 * @param string $path Request path.
	 * @param string $host Request authority.
	 * @return array|\WP_Error WordPress HTTP response.
	 */
	private static function request( string $path, string $host = self::PUBLIC_HOST ) {
		return wp_remote_get(
			self::HTTP_ORIGIN . $path,
			array(
				'redirection' => 0,
				'timeout'     => 5,
				'headers'     => array(
					'Host' => $host,
				),
			)
		);
	}
}
