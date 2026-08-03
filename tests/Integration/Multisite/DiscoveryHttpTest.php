<?php
/**
 * Slice 0 discovery and operation-gate HTTP integration tests.
 *
 * @package GalatanOvidiu\Charter
 */

declare(strict_types=1);

namespace GalatanOvidiu\Charter\Tests\Integration\Multisite;

use GalatanOvidiu\Charter\Tests\Prototype\Multisite\ActivationLifecycle;
use GalatanOvidiu\Charter\Tests\Prototype\Multisite\IssuerIdentity;
use GalatanOvidiu\Charter\Tests\Prototype\Multisite\NetworkAdminSelection;
use GalatanOvidiu\Charter\Tests\Prototype\Multisite\SiteIssuerLifecycle;
use WP_UnitTest_Factory;
use WP_UnitTestCase;

/**
 * Proves disposable discovery behavior through real local HTTP requests.
 *
 * @since 0.1.0
 */
final class DiscoveryHttpTest extends WP_UnitTestCase {

	/**
	 * The internal wp-env web-container address.
	 *
	 * @since 0.1.0
	 *
	 * @var string
	 */
	private const HTTP_ORIGIN = 'http://wordpress';

	/**
	 * Disposable sites committed so the independent web process can see them.
	 *
	 * @since 0.1.0
	 *
	 * @var array<string, int>
	 */
	private static array $siteIds = array();

	/**
	 * Creates real class fixtures before per-test transactions begin.
	 *
	 * @since 0.1.0
	 *
	 * @param WP_UnitTest_Factory $factory The WordPress test factory.
	 */
	public static function wpSetUpBeforeClass( WP_UnitTest_Factory $factory ): void {
		foreach ( self::siteDomains() as $name => $domain ) {
			self::$siteIds[ $name ] = $factory->blog->create(
				array(
					'domain' => $domain,
					'path'   => '/',
				)
			);
		}
	}

	/**
	 * Permanently removes the committed HTTP fixture sites after the class.
	 *
	 * @since 0.1.0
	 */
	public static function wpTearDownAfterClass(): void {
		require_once ABSPATH . 'wp-admin/includes/ms.php';
		require_once ABSPATH . 'wp-admin/includes/plugin.php';

		SiteIssuerLifecycle::resetProof();
		deactivate_plugins( plugin_basename( CHARTER_FILE ), true, true );

		foreach ( self::$siteIds as $siteId ) {
			wpmu_delete_blog( $siteId, true );
		}

		self::$siteIds = array();
	}

	/**
	 * Registers the disposable lifecycle proof and clears prior proof state.
	 *
	 * @since 0.1.0
	 */
	public function setUp(): void {
		parent::setUp();

		require_once ABSPATH . 'wp-admin/includes/plugin.php';

		ActivationLifecycle::register( CHARTER_FILE );
		SiteIssuerLifecycle::resetProof();
		deactivate_plugins( plugin_basename( CHARTER_FILE ), true, true );

		foreach ( self::$siteIds as $siteId ) {
			switch_to_blog( $siteId );
			deactivate_plugins( plugin_basename( CHARTER_FILE ), true, false );
			restore_current_blog();
		}
	}

	/**
	 * Verifies that an Available site publishes no Charter discovery document.
	 *
	 * @since 0.1.0
	 */
	public function testAvailableSitePublishesNoCharterDiscoveryDocument(): void {
		$siteId = self::siteId( 'available' );
		$issuer = IssuerIdentity::forSite( $siteId )->issuer();

		self::activateNetworkWide();
		self::commit_transaction();

		foreach ( self::discoveryPaths() as $path ) {
			$response = self::requestIssuerPath( $issuer, $path );

			self::assertNotWPError( $response );
			self::assertSame( 404, wp_remote_retrieve_response_code( $response ) );
			self::assertStringNotContainsString( 'application/json', wp_remote_retrieve_header( $response, 'content-type' ) );
			self::assertStringNotContainsString( '"issuer"', wp_remote_retrieve_body( $response ) );
			self::assertStringNotContainsString( '"resource"', wp_remote_retrieve_body( $response ) );
		}
	}

	/**
	 * Verifies Prepared discovery at both exact well-known request URLs.
	 *
	 * @since 0.1.0
	 */
	public function testPreparedSitePublishesExactDiscoveryWithoutOidcFallback(): void {
		$siteId = self::siteId( 'prepared' );
		$issuer = IssuerIdentity::forSite( $siteId )->issuer();

		self::activatePerSiteAndCommit( $siteId );

		$authorizationServerPath = '/.well-known/oauth-authorization-server';
		$authorizationServer     = self::requestIssuerPath( $issuer, $authorizationServerPath );

		self::assertNotWPError( $authorizationServer );
		self::assertSame(
			200,
			wp_remote_retrieve_response_code( $authorizationServer ),
			wp_remote_retrieve_header( $authorizationServer, 'location' )
		);
		self::assertStringContainsString( 'application/json', wp_remote_retrieve_header( $authorizationServer, 'content-type' ) );
		self::assertSame( $issuer . $authorizationServerPath, wp_remote_retrieve_header( $authorizationServer, 'content-location' ) );
		self::assertSame(
			array( 'issuer' => $issuer ),
			json_decode( wp_remote_retrieve_body( $authorizationServer ), true, 512, JSON_THROW_ON_ERROR )
		);

		$protectedResourcePath = '/.well-known/oauth-protected-resource';
		$protectedResource     = self::requestIssuerPath( $issuer, $protectedResourcePath );

		self::assertNotWPError( $protectedResource );
		self::assertSame( 200, wp_remote_retrieve_response_code( $protectedResource ) );
		self::assertStringContainsString( 'application/json', wp_remote_retrieve_header( $protectedResource, 'content-type' ) );
		self::assertSame( $issuer . $protectedResourcePath, wp_remote_retrieve_header( $protectedResource, 'content-location' ) );
		self::assertSame(
			array( 'resource' => $issuer ),
			json_decode( wp_remote_retrieve_body( $protectedResource ), true, 512, JSON_THROW_ON_ERROR )
		);

		$oidcFallback = self::requestIssuerPath( $issuer, '/.well-known/openid-configuration' );

		self::assertNotWPError( $oidcFallback );
		self::assertSame( 404, wp_remote_retrieve_response_code( $oidcFallback ) );
		self::assertStringNotContainsString( 'application/json', wp_remote_retrieve_header( $oidcFallback, 'content-type' ) );
	}

	/**
	 * Verifies that Prepared rejects a non-discovery operation over HTTP.
	 *
	 * @since 0.1.0
	 */
	public function testPreparedSiteRejectsNonDiscoveryOperationProbe(): void {
		$siteId = self::siteId( 'prepared-probe' );
		$issuer = IssuerIdentity::forSite( $siteId )->issuer();

		self::activatePerSiteAndCommit( $siteId );

		$response = self::requestIssuerPath( $issuer, '/charter-slice0-operation-probe' );

		self::assertNotWPError( $response );
		self::assertSame( 403, wp_remote_retrieve_response_code( $response ) );
		self::assertStringContainsString( 'application/json', wp_remote_retrieve_header( $response, 'content-type' ) );
		self::assertSame(
			array( 'error' => 'issuer_not_enabled' ),
			json_decode( wp_remote_retrieve_body( $response ), true, 512, JSON_THROW_ON_ERROR )
		);
	}

	/**
	 * Verifies that recorded verification enables only its exact issuer over HTTP.
	 *
	 * @since 0.1.0
	 */
	public function testRecordedVerificationEnablesOnlyExactIssuerOperation(): void {
		$verifiedSiteId   = self::siteId( 'verified' );
		$unverifiedSiteId = self::siteId( 'unverified' );
		$verifiedIssuer   = IssuerIdentity::forSite( $verifiedSiteId )->issuer();
		$unverifiedIssuer = IssuerIdentity::forSite( $unverifiedSiteId )->issuer();

		self::activateNetworkWide();
		NetworkAdminSelection::prepareSite( $verifiedSiteId );
		NetworkAdminSelection::prepareSite( $unverifiedSiteId );

		self::assertTrue( SiteIssuerLifecycle::recordVerification( $verifiedIssuer ) );
		self::assertFalse( SiteIssuerLifecycle::enable( $unverifiedIssuer ) );
		self::assertTrue( SiteIssuerLifecycle::enable( $verifiedIssuer ) );
		self::commit_transaction();

		$verifiedResponse = self::requestIssuerPath( $verifiedIssuer, '/charter-slice0-operation-probe' );

		self::assertNotWPError( $verifiedResponse );
		self::assertSame( 200, wp_remote_retrieve_response_code( $verifiedResponse ) );
		self::assertSame(
			array(
				'issuer' => $verifiedIssuer,
				'state'  => SiteIssuerLifecycle::ENABLED,
			),
			json_decode( wp_remote_retrieve_body( $verifiedResponse ), true, 512, JSON_THROW_ON_ERROR )
		);

		$unverifiedResponse = self::requestIssuerPath( $unverifiedIssuer, '/charter-slice0-operation-probe' );

		self::assertNotWPError( $unverifiedResponse );
		self::assertSame( 403, wp_remote_retrieve_response_code( $unverifiedResponse ) );
		self::assertSame(
			array( 'error' => 'issuer_not_enabled' ),
			json_decode( wp_remote_retrieve_body( $unverifiedResponse ), true, 512, JSON_THROW_ON_ERROR )
		);
	}

	/**
	 * Verifies that one Enabled sibling does not change other HTTP surfaces.
	 *
	 * @since 0.1.0
	 */
	public function testEnabledSiblingDoesNotAffectAvailableOrPreparedSites(): void {
		$enabledSiteId   = self::siteId( 'enabled-sibling' );
		$preparedSiteId  = self::siteId( 'prepared-sibling' );
		$availableSiteId = self::siteId( 'available-sibling' );
		$enabledIssuer   = IssuerIdentity::forSite( $enabledSiteId )->issuer();
		$preparedIssuer  = IssuerIdentity::forSite( $preparedSiteId )->issuer();
		$availableIssuer = IssuerIdentity::forSite( $availableSiteId )->issuer();

		self::activateNetworkWide();
		NetworkAdminSelection::prepareSite( $enabledSiteId );
		NetworkAdminSelection::prepareSite( $preparedSiteId );

		self::assertTrue( SiteIssuerLifecycle::recordVerification( $enabledIssuer ) );
		self::assertTrue( SiteIssuerLifecycle::enable( $enabledIssuer ) );
		self::commit_transaction();

		$enabledDiscovery   = self::requestIssuerPath( $enabledIssuer, '/.well-known/oauth-authorization-server' );
		$enabledOperation   = self::requestIssuerPath( $enabledIssuer, '/charter-slice0-operation-probe' );
		$preparedDiscovery  = self::requestIssuerPath( $preparedIssuer, '/.well-known/oauth-authorization-server' );
		$preparedResource   = self::requestIssuerPath( $preparedIssuer, '/.well-known/oauth-protected-resource' );
		$preparedOperation  = self::requestIssuerPath( $preparedIssuer, '/charter-slice0-operation-probe' );
		$availableDiscovery = self::requestIssuerPath( $availableIssuer, '/.well-known/oauth-authorization-server' );
		$availableResource  = self::requestIssuerPath( $availableIssuer, '/.well-known/oauth-protected-resource' );
		$availableOperation = self::requestIssuerPath( $availableIssuer, '/charter-slice0-operation-probe' );

		self::assertNotWPError( $enabledDiscovery );
		self::assertNotWPError( $enabledOperation );
		self::assertNotWPError( $preparedDiscovery );
		self::assertNotWPError( $preparedResource );
		self::assertNotWPError( $preparedOperation );
		self::assertNotWPError( $availableDiscovery );
		self::assertNotWPError( $availableResource );
		self::assertNotWPError( $availableOperation );

		self::assertSame( 200, wp_remote_retrieve_response_code( $enabledDiscovery ) );
		self::assertSame( 200, wp_remote_retrieve_response_code( $enabledOperation ) );
		self::assertSame( 200, wp_remote_retrieve_response_code( $preparedDiscovery ) );
		self::assertSame( 200, wp_remote_retrieve_response_code( $preparedResource ) );
		self::assertSame( 403, wp_remote_retrieve_response_code( $preparedOperation ) );
		self::assertSame( 404, wp_remote_retrieve_response_code( $availableDiscovery ) );
		self::assertSame( 404, wp_remote_retrieve_response_code( $availableResource ) );
		self::assertSame( 404, wp_remote_retrieve_response_code( $availableOperation ) );
	}

	/**
	 * Activates Charter network-wide through WordPress's public lifecycle seam.
	 *
	 * @since 0.1.0
	 */
	private static function activateNetworkWide(): void {
		$activationResult = activate_plugin(
			plugin_basename( CHARTER_FILE ),
			'',
			true
		);

		self::assertNull( $activationResult );
	}

	/**
	 * Activates one site and commits its state for the independent web process.
	 *
	 * @since 0.1.0
	 *
	 * @param int $siteId The WordPress site locator.
	 */
	private static function activatePerSiteAndCommit( int $siteId ): void {
		switch_to_blog( $siteId );
		$activationResult = activate_plugin( plugin_basename( CHARTER_FILE ) );
		restore_current_blog();

		self::assertNull( $activationResult );
		self::commit_transaction();
	}

	/**
	 * Returns one committed HTTP fixture site locator.
	 *
	 * @since 0.1.0
	 *
	 * @param string $name The fixture name.
	 * @return int The WordPress site locator.
	 */
	private static function siteId( string $name ): int {
		return self::$siteIds[ $name ];
	}

	/**
	 * Returns the public origins reserved for HTTP proof cases.
	 *
	 * @since 0.1.0
	 *
	 * @return array<string, string> Fixture name to public domain.
	 */
	private static function siteDomains(): array {
		return array(
			'available'         => 'available-discovery.example.org',
			'prepared'          => 'prepared-discovery.example.org',
			'prepared-probe'    => 'prepared-probe.example.org',
			'verified'          => 'verified-operation.example.org',
			'unverified'        => 'unverified-operation.example.org',
			'enabled-sibling'   => 'enabled-sibling.example.org',
			'prepared-sibling'  => 'prepared-sibling.example.org',
			'available-sibling' => 'available-sibling.example.org',
		);
	}

	/**
	 * Returns the two root discovery paths approved for the proof.
	 *
	 * @since 0.1.0
	 *
	 * @return list<string> The exact HTTP request paths.
	 */
	private static function discoveryPaths(): array {
		return array(
			'/.well-known/oauth-authorization-server',
			'/.well-known/oauth-protected-resource',
		);
	}

	/**
	 * Performs a real HTTP GET while resolving the public issuer to wp-env.
	 *
	 * @since 0.1.0
	 *
	 * @param string $issuer The exact public issuer.
	 * @param string $path   The HTTP request path.
	 * @return array|\WP_Error The WordPress HTTP response.
	 */
	private static function requestIssuerPath( string $issuer, string $path ) {
		return wp_remote_get(
			self::HTTP_ORIGIN . $path,
			array(
				'redirection' => 0,
				'headers'     => array(
					'Host' => self::publicAuthority( $issuer ),
				),
			)
		);
	}

	/**
	 * Returns the issuer authority used for local Host resolution.
	 *
	 * @since 0.1.0
	 *
	 * @param string $issuer The exact public issuer.
	 * @return string The host and optional port.
	 */
	private static function publicAuthority( string $issuer ): string {
		$host = (string) wp_parse_url( $issuer, PHP_URL_HOST );
		$port = wp_parse_url( $issuer, PHP_URL_PORT );

		return is_int( $port ) ? $host . ':' . $port : $host;
	}
}
