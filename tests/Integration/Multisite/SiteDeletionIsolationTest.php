<?php
/**
 * Slice 0 site-deletion isolation integration tests.
 *
 * @package GalatanOvidiu\Charter
 */

declare(strict_types=1);

namespace GalatanOvidiu\Charter\Tests\Integration\Multisite;

use GalatanOvidiu\Charter\Tests\Prototype\Multisite\IssuerIdentity;
use GalatanOvidiu\Charter\Tests\Prototype\Multisite\ProofCredentialStore;
use GalatanOvidiu\Charter\Tests\Prototype\Multisite\SiteDeletionLifecycle;
use GalatanOvidiu\Charter\Tests\Prototype\Multisite\SiteIssuerLifecycle;
use WP_Site;
use WP_UnitTestCase;

/**
 * Proves cleanup behavior through WordPress's public site-deletion lifecycle.
 *
 * @since 0.1.0
 */
final class SiteDeletionIsolationTest extends WP_UnitTestCase {

	/**
	 * Clears disposable proof records before each proof case.
	 *
	 * @since 0.1.0
	 */
	public function setUp(): void {
		parent::setUp();

		SiteDeletionLifecycle::register();
		SiteIssuerLifecycle::resetProof();
		ProofCredentialStore::resetProof();
	}

	/**
	 * Verifies that permanent deletion removes only the target authority.
	 *
	 * @since 0.1.0
	 */
	public function testPermanentSiteDeletionRemovesOnlyTargetIssuerAuthority(): void {
		$deletedSiteId   = self::createOriginAddressedSite( 'deleted-authority.example.org' );
		$siblingSiteId   = self::createOriginAddressedSite( 'surviving-authority.example.org' );
		$deletedIdentity = IssuerIdentity::forSite( $deletedSiteId );
		$siblingIdentity = IssuerIdentity::forSite( $siblingSiteId );

		self::enableIdentity( $deletedIdentity );
		self::enableIdentity( $siblingIdentity );
		ProofCredentialStore::issue( 'deleted-site-credential', $deletedIdentity, $deletedIdentity->issuer() );
		ProofCredentialStore::issue( 'sibling-site-credential', $siblingIdentity, $siblingIdentity->issuer() );

		$deletionResult = wp_delete_site( $deletedSiteId );

		self::assertInstanceOf( WP_Site::class, $deletionResult );
		self::assertFalse( SiteIssuerLifecycle::hasIssuer( $deletedIdentity->issuer() ) );
		self::assertSame( SiteIssuerLifecycle::AVAILABLE, SiteIssuerLifecycle::stateFor( $deletedIdentity->issuer() ) );
		self::assertFalse(
			ProofCredentialStore::accepts(
				'deleted-site-credential',
				$deletedIdentity,
				$deletedIdentity->issuer()
			)
		);

		self::assertTrue( SiteIssuerLifecycle::hasIssuer( $siblingIdentity->issuer() ) );
		self::assertSame( SiteIssuerLifecycle::ENABLED, SiteIssuerLifecycle::stateFor( $siblingIdentity->issuer() ) );
		self::assertTrue(
			ProofCredentialStore::accepts(
				'sibling-site-credential',
				$siblingIdentity,
				$siblingIdentity->issuer()
			)
		);
	}

	/**
	 * Verifies that recreating a deleted public origin starts fresh authority.
	 *
	 * @since 0.1.0
	 */
	public function testRecreatedDomainDoesNotResurrectDeletedIssuerOrCredential(): void {
		$deletedSiteId   = self::createOriginAddressedSite( 'recreated-authority.example.org' );
		$deletedIdentity = IssuerIdentity::forSite( $deletedSiteId );
		$issuer          = $deletedIdentity->issuer();

		self::enableIdentity( $deletedIdentity );
		ProofCredentialStore::issue( 'prior-site-credential', $deletedIdentity, $issuer );

		$deletionResult    = wp_delete_site( $deletedSiteId );
		$recreatedSiteId   = self::createOriginAddressedSite( 'recreated-authority.example.org' );
		$recreatedIdentity = IssuerIdentity::forSite( $recreatedSiteId );

		self::assertInstanceOf( WP_Site::class, $deletionResult );
		self::assertNotSame( $deletedSiteId, $recreatedSiteId );
		self::assertSame( $issuer, $recreatedIdentity->issuer() );
		self::assertFalse( SiteIssuerLifecycle::hasIssuer( $issuer ) );
		self::assertSame( SiteIssuerLifecycle::AVAILABLE, SiteIssuerLifecycle::stateFor( $issuer ) );

		self::enableIdentity( $recreatedIdentity );

		self::assertFalse(
			ProofCredentialStore::accepts(
				'prior-site-credential',
				$recreatedIdentity,
				$issuer
			)
		);

		ProofCredentialStore::issue( 'recreated-site-credential', $recreatedIdentity, $issuer );
		self::assertTrue(
			ProofCredentialStore::accepts(
				'recreated-site-credential',
				$recreatedIdentity,
				$issuer
			)
		);
	}

	/**
	 * Moves one explicit issuer identity to Enabled.
	 *
	 * @since 0.1.0
	 *
	 * @param IssuerIdentity $identity The issuer identity to enable.
	 */
	private static function enableIdentity( IssuerIdentity $identity ): void {
		SiteIssuerLifecycle::prepare( $identity );
		self::assertTrue( SiteIssuerLifecycle::recordVerification( $identity->issuer() ) );
		self::assertTrue( SiteIssuerLifecycle::enable( $identity->issuer() ) );
	}

	/**
	 * Creates a supported origin-addressed Multisite site.
	 *
	 * @since 0.1.0
	 *
	 * @param string $domain The site's public domain.
	 * @return int The WordPress site locator.
	 */
	private static function createOriginAddressedSite( string $domain ): int {
		return self::factory()->blog->create(
			array(
				'domain' => $domain,
				'path'   => '/',
			)
		);
	}
}
