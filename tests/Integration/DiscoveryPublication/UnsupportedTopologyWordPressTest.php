<?php
/**
 * Slice 0 unsupported-topology WordPress integration tests.
 *
 * @package GalatanOvidiu\Charter
 */

declare(strict_types=1);

namespace GalatanOvidiu\Charter\Tests\Integration\DiscoveryPublication;

use GalatanOvidiu\Charter\Tests\Prototype\DiscoveryPublication\MetadataProjector;
use GalatanOvidiu\Charter\Tests\Prototype\DiscoveryPublication\SetupPresentation;
use GalatanOvidiu\Charter\Tests\Prototype\DiscoveryPublication\UnsupportedTopologyDiagnostics;
use GalatanOvidiu\Charter\Tests\Prototype\DiscoveryPublication\VerificationLedger;
use GalatanOvidiu\Charter\Tests\Prototype\Multisite\ActivationLifecycle;
use GalatanOvidiu\Charter\Tests\Prototype\Multisite\SiteIssuerLifecycle;
use InvalidArgumentException;
use WP_UnitTestCase;

/**
 * Proves real WordPress diagnostic hooks for a path-bearing single site.
 *
 * @since 0.1.0
 */
final class UnsupportedTopologyWordPressTest extends WP_UnitTestCase {

	/**
	 * Internal wp-env web-container origin.
	 *
	 * @var string
	 */
	private const HTTP_ORIGIN = 'http://wordpress';

	/**
	 * Registers the proof callbacks and establishes a path-bearing home URL.
	 *
	 * @since 0.1.0
	 */
	public function setUp(): void {
		parent::setUp();

		require_once ABSPATH . 'wp-admin/includes/plugin.php';

		deactivate_plugins( plugin_basename( CHARTER_FILE ), true, true );
		SiteIssuerLifecycle::resetProof();
		update_option( 'home', 'https://single-site.charter.test/team' );
		update_option( 'siteurl', 'https://single-site.charter.test/team' );
		add_filter( 'home_url', array( self::class, 'pathBearingHomeUrl' ) );
		ActivationLifecycle::register( CHARTER_FILE );
		UnsupportedTopologyDiagnostics::register();
	}

	/**
	 * Verifies activation plus equivalent persistent diagnostic surfaces.
	 *
	 * @since 0.1.0
	 */
	public function testPathBearingSingleSiteRemainsActiveAndFailsClosedWithExactDiagnostics(): void {
		$canonicalBase = 'https://single-site.charter.test/team';

		self::assertSame( $canonicalBase, untrailingslashit( get_home_url( get_current_blog_id() ) ) );

		$activationResult = activate_plugin( plugin_basename( CHARTER_FILE ) );

		self::assertNull( $activationResult );
		self::assertTrue( is_plugin_active( plugin_basename( CHARTER_FILE ) ) );
		self::assertSame( SiteIssuerLifecycle::PREPARED, SiteIssuerLifecycle::stateFor( $canonicalBase ) );

		ob_start();
		// phpcs:ignore WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedHooknameFound -- Invokes the WordPress core hook to prove the registered surface.
		do_action( 'admin_notices' );
		$administratorNotice = (string) ob_get_clean();

		// phpcs:ignore WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedHooknameFound -- Invokes the WordPress core filter to prove the registered surface.
		$siteHealthTests = apply_filters( 'site_status_tests', array() );
		$siteHealth      = call_user_func( $siteHealthTests['direct']['charter_unsupported_path_topology']['test'] );
		$diagnostics     = UnsupportedTopologyDiagnostics::forCanonicalBase( $canonicalBase );

		self::assertSame( $diagnostics['administrator_notice'], $administratorNotice );
		self::assertStringNotContainsString( 'is-dismissible', $administratorNotice );
		self::assertSame( 'critical', $siteHealth['status'] );
		self::assertSame( $diagnostics['message'], $siteHealth['description'] );
		self::assertSame( $diagnostics['message'], $diagnostics['wp_cli']['message'] );

		$this->expectException( InvalidArgumentException::class );
		( new VerificationLedger() )->prepare( $canonicalBase );
	}

	/**
	 * Verifies no discovery projection can be constructed for the site.
	 *
	 * @since 0.1.0
	 */
	public function testPathBearingSingleSiteCannotProjectCharterMetadata(): void {
		$this->expectException( InvalidArgumentException::class );

		MetadataProjector::authorizationServerMetadata( 'https://single-site.charter.test/team' );
	}

	/**
	 * Verifies real HTTP remains operational without exposing Charter surfaces.
	 *
	 * @since 0.1.0
	 */
	public function testPathBearingSingleSitePublishesNoCharterHttpBehavior(): void {
		$activationResult = activate_plugin( plugin_basename( CHARTER_FILE ) );

		self::assertNull( $activationResult );
		self::commit_transaction();

		foreach (
			array(
				'/.well-known/oauth-authorization-server',
				'/.well-known/oauth-authorization-server/team',
				'/.well-known/oauth-protected-resource',
				'/.well-known/oauth-protected-resource/team',
				'/team/.well-known/oauth-authorization-server',
				'/team/.well-known/oauth-protected-resource',
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
		self::assertTrue( is_plugin_active( plugin_basename( CHARTER_FILE ) ) );
	}

	/**
	 * Verifies WordPress REST permalink settings cannot move OAuth discovery.
	 *
	 * @since 0.1.0
	 */
	public function testPrettyAndPlainRestRoutesDoNotChangeDiscoveryUrls(): void {
		global $wp_rewrite;

		remove_filter( 'home_url', array( self::class, 'pathBearingHomeUrl' ) );

		$issuer       = 'https://issuer.charter.test';
		$presentation = SetupPresentation::forIssuer( $issuer );

		$wp_rewrite->set_permalink_structure( '' );
		$plainRestUrl = get_rest_url();

		$wp_rewrite->set_permalink_structure( '/%postname%/' );
		$prettyRestUrl = get_rest_url();

		self::assertNotSame( $plainRestUrl, $prettyRestUrl );
		self::assertStringContainsString( 'rest_route=', $plainRestUrl );
		self::assertStringContainsString( '/wp-json/', $prettyRestUrl );
		self::assertSame(
			array(
				$issuer . '/.well-known/oauth-authorization-server',
				$issuer . '/.well-known/oauth-protected-resource',
			),
			$presentation['verification_urls']
		);
	}

	/**
	 * Supplies the exact path-bearing identity for the single-site diagnostic.
	 *
	 * @since 0.1.0
	 *
	 * @return string Canonical path-bearing home URL.
	 */
	public static function pathBearingHomeUrl(): string {
		return 'https://single-site.charter.test/team';
	}

	/**
	 * Performs one bounded independent WordPress HTTP request.
	 *
	 * @param string $path Request path.
	 * @return array|\WP_Error WordPress HTTP response.
	 */
	private static function request( string $path ) {
		return wp_remote_get(
			self::HTTP_ORIGIN . $path,
			array(
				'redirection' => 0,
				'timeout'     => 5,
				'headers'     => array(
					'Host' => 'single-site.charter.test',
				),
			)
		);
	}
}
