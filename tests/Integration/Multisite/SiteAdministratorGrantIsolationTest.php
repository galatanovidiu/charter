<?php
/**
 * Production site-administrator grant isolation on Multisite.
 *
 * @package GalatanOvidiu\Charter
 */

declare(strict_types=1);

namespace GalatanOvidiu\Charter\Tests\Integration\Multisite;

use GalatanOvidiu\Charter\OAuth\AuthorizationRequest;
use GalatanOvidiu\Charter\OAuth\Client;
use GalatanOvidiu\Charter\OAuth\CredentialHasher;
use GalatanOvidiu\Charter\OAuth\CredentialStore;
use GalatanOvidiu\Charter\OAuth\GrantGovernance;
use GalatanOvidiu\Charter\OAuth\GrantRecord;
use GalatanOvidiu\Charter\Plugin;
use GalatanOvidiu\Charter\Schema;
use GalatanOvidiu\Charter\Security\AuditLog;
use WP_UnitTestCase;

/**
 * Verifies same-number grant records remain isolated by site table and issuer.
 *
 * @since 0.1.0
 */
final class SiteAdministratorGrantIsolationTest extends WP_UnitTestCase {
	/**
	 * First site fixture locator.
	 *
	 * @var int
	 */
	private static int $firstSiteId;

	/**
	 * Second site fixture locator.
	 *
	 * @var int
	 */
	private static int $secondSiteId;

	/** Creates site tables outside the per-test database transaction. */
	public static function set_up_before_class(): void {
		parent::set_up_before_class();
		self::$firstSiteId  = self::createSite( 'grant-admin-one.example.org' );
		self::$secondSiteId = self::createSite( 'grant-admin-two.example.org' );
		foreach ( array( self::$firstSiteId, self::$secondSiteId ) as $siteId ) {
			switch_to_blog( $siteId );
			try {
				Schema::install();
			} finally {
				restore_current_blog();
			}
		}
	}

	/** Deletes the fixture sites after their production tables are no longer needed. */
	public static function tear_down_after_class(): void {
		wp_delete_site( self::$firstSiteId );
		wp_delete_site( self::$secondSiteId );
		parent::tear_down_after_class();
	}

	/** Verifies one site action cannot inspect or close a sibling-site grant. */
	public function testGrantGovernanceRemainsInsideCurrentSiteAndExactIssuer(): void {
		$firstIssuer  = 'https://grant-admin-one.example.org';
		$secondIssuer = 'https://grant-admin-two.example.org';
		$plugin       = Plugin::boot();
		$store        = new CredentialStore( new CredentialHasher( $plugin->signingKeys() ) );

		switch_to_blog( self::$firstSiteId );
		try {
			$store->deleteAll();
			( new AuditLog() )->deleteAll();
			$firstGrant = self::issueGrant( $store, $firstIssuer, 'first-site-client', 101 );
		} finally {
			restore_current_blog();
		}

		switch_to_blog( self::$secondSiteId );
		try {
			$store->deleteAll();
			$audit       = new AuditLog();
			$governance  = new GrantGovernance( $store, $audit );
			$secondGrant = self::issueGrant( $store, $secondIssuer, 'second-site-client', 202 );
			self::assertSame( $firstGrant->id(), $secondGrant->id(), 'The isolation case requires colliding site-local identifiers.' );
			self::assertNull( $governance->revoke( $firstIssuer, $firstGrant->id(), 1, time() ) );
			self::assertCount( 1, $store->listActiveGrantsForIssuer( $secondIssuer ) );
			self::assertSame( array(), $audit->listForIssuer( $secondIssuer ) );
		} finally {
			restore_current_blog();
		}

		switch_to_blog( self::$firstSiteId );
		try {
			$audit      = new AuditLog();
			$governance = new GrantGovernance( $store, $audit );
			self::assertInstanceOf( GrantRecord::class, $governance->revoke( $firstIssuer, $firstGrant->id(), 1, time() ) );
			self::assertSame( array(), $store->listActiveGrantsForIssuer( $firstIssuer ) );
			self::assertCount( 1, $audit->listForIssuer( $firstIssuer ) );
		} finally {
			restore_current_blog();
		}

		switch_to_blog( self::$secondSiteId );
		try {
			self::assertCount( 1, $store->listActiveGrantsForIssuer( $secondIssuer ) );
			self::assertSame( array(), ( new AuditLog() )->listForIssuer( $secondIssuer ) );
		} finally {
			restore_current_blog();
		}
	}

	/**
	 * Issues one grant and one descendant authorization code in the current site table.
	 *
	 * @param CredentialStore $store Current-site credential persistence.
	 * @param string          $issuer Exact current site issuer.
	 * @param string          $clientId Exact client identifier.
	 * @param int             $userId Represented WordPress user.
	 */
	private static function issueGrant( CredentialStore $store, string $issuer, string $clientId, int $userId ): GrantRecord {
		$client      = new Client( $issuer, $clientId, $clientId, array( 'https://' . $clientId . '.example.test/callback' ) );
		$request     = new AuthorizationRequest( $issuer, $issuer, $client, $client->redirectUris()[0], 'wordpress:access', str_repeat( 'a', 43 ), null ); // phpcs:ignore WordPress.WP.CapitalPDangit.MisspelledInText -- Exact OAuth scope token.
		$transaction = $store->issueAuthorizationRequest( $request, $userId, time() );
		$record      = $store->find( CredentialStore::AUTHORIZATION_REQUEST, $issuer, $transaction );
		self::assertNotNull( $record );
		self::assertIsString( $store->approveAuthorization( $record, time() ) );
		$grants = $store->listActiveGrantsForUser( $issuer, $userId );
		self::assertCount( 1, $grants );

		return $grants[0];
	}

	/**
	 * Creates one supported origin-addressed Multisite site.
	 *
	 * @param string $domain Public site domain.
	 */
	private static function createSite( string $domain ): int {
		return self::factory()->blog->create(
			array(
				'domain' => $domain,
				'path'   => '/',
			)
		);
	}
}
