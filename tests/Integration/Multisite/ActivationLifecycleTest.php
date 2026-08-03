<?php
/**
 * Slice 0 activation lifecycle integration tests.
 *
 * @package GalatanOvidiu\Charter
 */

declare(strict_types=1);

namespace GalatanOvidiu\Charter\Tests\Integration\Multisite;

use GalatanOvidiu\Charter\Tests\Prototype\Multisite\ActivationLifecycle;
use GalatanOvidiu\Charter\Tests\Prototype\Multisite\IssuerIdentity;
use GalatanOvidiu\Charter\Tests\Prototype\Multisite\NetworkAdminSelection;
use GalatanOvidiu\Charter\Tests\Prototype\Multisite\SiteIssuerLifecycle;
use WP_UnitTestCase;

/**
 * Proves activation behavior through WordPress's public plugin lifecycle.
 *
 * @since 0.1.0
 */
final class ActivationLifecycleTest extends WP_UnitTestCase {

	/**
	 * Registers the disposable activation proof and clears prior proof state.
	 *
	 * @since 0.1.0
	 */
	public function setUp(): void {
		parent::setUp();

		require_once ABSPATH . 'wp-admin/includes/plugin.php';

		ActivationLifecycle::register( CHARTER_FILE );
		SiteIssuerLifecycle::resetProof();
		deactivate_plugins( plugin_basename( CHARTER_FILE ), true, true );
	}

	/**
	 * Verifies that network activation leaves every existing site Available.
	 *
	 * @since 0.1.0
	 */
	public function testNetworkActivationLeavesExistingSitesAvailableWithoutDiscoveryMetadata(): void {
		self::createOriginAddressedSite( 'existing-one.example.org' );
		self::createOriginAddressedSite( 'existing-two.example.org' );

		self::activateNetworkWide();

		$siteIds = get_sites(
			array(
				'fields' => 'ids',
				'number' => 0,
			)
		);

		foreach ( $siteIds as $siteId ) {
			$issuer = IssuerIdentity::forSite( (int) $siteId )->issuer();

			self::assertSame( SiteIssuerLifecycle::AVAILABLE, SiteIssuerLifecycle::stateFor( $issuer ) );
			self::assertFalse( SiteIssuerLifecycle::hasIssuer( $issuer ) );
		}
	}

	/**
	 * Verifies that per-site activation prepares only the activated site.
	 *
	 * @since 0.1.0
	 */
	public function testPerSiteActivationPreparesOnlyTheActivatedSite(): void {
		$activatedSiteId = self::createOriginAddressedSite( 'activated.example.org' );
		$siblingSiteId   = self::createOriginAddressedSite( 'activation-sibling.example.org' );
		$activatedIssuer = IssuerIdentity::forSite( $activatedSiteId )->issuer();
		$siblingIssuer   = IssuerIdentity::forSite( $siblingSiteId )->issuer();

		switch_to_blog( $activatedSiteId );
		$activationResult = activate_plugin( plugin_basename( CHARTER_FILE ) );
		restore_current_blog();

		self::assertNull( $activationResult );
		self::assertSame( SiteIssuerLifecycle::PREPARED, SiteIssuerLifecycle::stateFor( $activatedIssuer ) );
		self::assertTrue( SiteIssuerLifecycle::hasIssuer( $activatedIssuer ) );
		self::assertSame( SiteIssuerLifecycle::AVAILABLE, SiteIssuerLifecycle::stateFor( $siblingIssuer ) );
		self::assertFalse( SiteIssuerLifecycle::hasIssuer( $siblingIssuer ) );
	}

	/**
	 * Verifies that Network Admin selection prepares only the selected site.
	 *
	 * @since 0.1.0
	 */
	public function testNetworkAdminSelectionPreparesOnlyTheSelectedSite(): void {
		$selectedSiteId = self::createOriginAddressedSite( 'selected.example.org' );
		$siblingSiteId  = self::createOriginAddressedSite( 'selection-sibling.example.org' );
		$selectedIssuer = IssuerIdentity::forSite( $selectedSiteId )->issuer();
		$siblingIssuer  = IssuerIdentity::forSite( $siblingSiteId )->issuer();

		self::activateNetworkWide();

		NetworkAdminSelection::prepareSite( $selectedSiteId );

		self::assertSame( SiteIssuerLifecycle::PREPARED, SiteIssuerLifecycle::stateFor( $selectedIssuer ) );
		self::assertSame( SiteIssuerLifecycle::AVAILABLE, SiteIssuerLifecycle::stateFor( $siblingIssuer ) );
		self::assertFalse( SiteIssuerLifecycle::hasIssuer( $siblingIssuer ) );
	}

	/**
	 * Verifies that a site created after network activation remains Available.
	 *
	 * @since 0.1.0
	 */
	public function testSiteCreatedAfterNetworkActivationRemainsAvailableWithoutDiscoveryMetadata(): void {
		self::activateNetworkWide();

		$newSiteId = self::createOriginAddressedSite( 'new-site.example.org' );
		$newIssuer = IssuerIdentity::forSite( $newSiteId )->issuer();

		self::assertSame( SiteIssuerLifecycle::AVAILABLE, SiteIssuerLifecycle::stateFor( $newIssuer ) );
		self::assertFalse( SiteIssuerLifecycle::hasIssuer( $newIssuer ) );
	}

	/**
	 * Verifies that one issuer's verification cannot enable a sibling issuer.
	 *
	 * @since 0.1.0
	 */
	public function testRecordedVerificationEnablesOnlyTheExactIssuer(): void {
		$verifiedSiteId = self::createOriginAddressedSite( 'verified.example.org' );
		$siblingSiteId  = self::createOriginAddressedSite( 'verification-sibling.example.org' );
		$verifiedIssuer = IssuerIdentity::forSite( $verifiedSiteId )->issuer();
		$siblingIssuer  = IssuerIdentity::forSite( $siblingSiteId )->issuer();

		self::activateNetworkWide();

		NetworkAdminSelection::prepareSite( $verifiedSiteId );

		self::assertSame( SiteIssuerLifecycle::PREPARED, SiteIssuerLifecycle::stateFor( $verifiedIssuer ) );
		self::assertSame( SiteIssuerLifecycle::AVAILABLE, SiteIssuerLifecycle::stateFor( $siblingIssuer ) );
		self::assertTrue( SiteIssuerLifecycle::recordVerification( $verifiedIssuer ) );
		self::assertFalse( SiteIssuerLifecycle::enable( $siblingIssuer ) );
		self::assertSame( SiteIssuerLifecycle::AVAILABLE, SiteIssuerLifecycle::stateFor( $siblingIssuer ) );
		self::assertFalse( SiteIssuerLifecycle::hasIssuer( $siblingIssuer ) );
		self::assertTrue( SiteIssuerLifecycle::enable( $verifiedIssuer ) );
		self::assertSame( SiteIssuerLifecycle::ENABLED, SiteIssuerLifecycle::stateFor( $verifiedIssuer ) );
		self::assertSame( SiteIssuerLifecycle::AVAILABLE, SiteIssuerLifecycle::stateFor( $siblingIssuer ) );
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
