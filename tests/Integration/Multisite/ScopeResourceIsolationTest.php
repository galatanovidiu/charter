<?php
/**
 * Production specialized resource Multisite integration tests.
 *
 * @package GalatanOvidiu\Charter
 */

declare(strict_types=1);

namespace GalatanOvidiu\Charter\Tests\Integration\Multisite;

use GalatanOvidiu\Charter\OAuth\AccessPolicy;
use GalatanOvidiu\Charter\Plugin;
use WP_UnitTestCase;

/**
 * Verifies request-local integration registrations remain issuer-isolated.
 *
 * @since 0.1.0
 */
final class ScopeResourceIsolationTest extends WP_UnitTestCase {

	/** Registers the test integration for each exact issuer policy. */
	public function setUp(): void {
		parent::setUp();
		add_action( 'charter_oauth_register_access', array( $this, 'registerMcpResource' ), 10, 2 );
	}

	/** Removes the request-local test integration. */
	public function tearDown(): void {
		remove_action( 'charter_oauth_register_access', array( $this, 'registerMcpResource' ), 10 );
		parent::tearDown();
	}

	/** Verifies two site policies cannot see or accept each other's resource. */
	public function testSpecializedResourceAssociationsRemainExactPerSiteIssuer(): void {
		$firstSiteId    = self::createOriginAddressedSite( 'scope-one.example.org' );
		$secondSiteId   = self::createOriginAddressedSite( 'scope-two.example.org' );
		$firstIssuer    = self::prepareIssuer( $firstSiteId );
		$secondIssuer   = self::prepareIssuer( $secondSiteId );
		$provider       = Plugin::boot()->accessPolicy();
		$firstPolicy    = $provider->forIssuer( $firstIssuer );
		$secondPolicy   = $provider->forIssuer( $secondIssuer );
		$firstResource  = self::resourceForIssuer( $firstIssuer );
		$secondResource = self::resourceForIssuer( $secondIssuer );

		self::assertNotSame( $firstIssuer, $secondIssuer );
		self::assertTrue( $firstPolicy->bindingAvailable( $firstResource, 'example-mcp:access' ) );
		self::assertFalse( $firstPolicy->hasResource( $secondResource ) );
		self::assertTrue( $secondPolicy->bindingAvailable( $secondResource, 'example-mcp:access' ) );
		self::assertFalse( $secondPolicy->hasResource( $firstResource ) );
		self::assertNull( $firstPolicy->canonicalScope( $secondResource, array( 'example-mcp:access' ) ) );
		self::assertNull( $secondPolicy->canonicalScope( $firstResource, array( 'example-mcp:access' ) ) );
	}

	/**
	 * Registers one MCP-server-wide scope under the exact supplied issuer.
	 *
	 * @param AccessPolicy $policy Exact issuer policy under construction.
	 * @param string       $issuer Exact current issuer.
	 */
	public function registerMcpResource( AccessPolicy $policy, string $issuer ): void {
		$resource = self::resourceForIssuer( $issuer );
		self::assertTrue( $policy->registerResource( 'example-mcp', $resource ) );
		self::assertTrue(
			$policy->registerScope(
				'example-mcp',
				'example-mcp:access',
				'Example MCP access',
				'Use the Example MCP server as your WordPress account.',
				array( $resource )
			)
		);
	}

	/**
	 * Prepares and returns one exact production site issuer.
	 *
	 * @param int $siteId Exact WordPress site identifier.
	 */
	private static function prepareIssuer( int $siteId ): string {
		switch_to_blog( $siteId );
		$siteUrlFilter = static fn ( string $url ): string => preg_replace( '/^http:/', 'https:', $url ) ?? $url;
		add_filter( 'site_url', $siteUrlFilter );
		try {
			$state = Plugin::boot()->siteState();
			$state->delete();
			$prepared = $state->prepareCurrentSite();
			$record   = get_option( 'charter_oauth_site_state', array() );
			$error    = is_array( $record ) && is_string( $record['error'] ?? null ) ? $record['error'] : 'unknown_preparation_error';
			self::assertTrue( $prepared, $error );
			$identity = $state->identity();
			self::assertNotNull( $identity );

			return $identity->issuer();
		} finally {
			remove_filter( 'site_url', $siteUrlFilter );
			restore_current_blog();
		}
	}

	/**
	 * Returns the exact path-bearing MCP resource under one site issuer.
	 *
	 * @param string $issuer Exact site issuer.
	 */
	private static function resourceForIssuer( string $issuer ): string {
		return $issuer . '/wp-json/example-mcp/v1';
	}

	/**
	 * Creates one supported origin-addressed Multisite site.
	 *
	 * @param string $domain Supported site domain.
	 */
	private static function createOriginAddressedSite( string $domain ): int {
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
}
