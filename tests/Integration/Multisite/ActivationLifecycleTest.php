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
		self::factory()->blog->create();
		self::factory()->blog->create();

		$activationResult = activate_plugin(
			plugin_basename( CHARTER_FILE ),
			'',
			true
		);

		self::assertNull( $activationResult );

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
			self::assertFalse( SiteIssuerLifecycle::publishesDiscoveryFor( $issuer ) );
		}
	}

	/**
	 * Verifies that per-site activation prepares only the activated site.
	 *
	 * @since 0.1.0
	 */
	public function testPerSiteActivationPreparesOnlyTheActivatedSite(): void {
		$activatedSiteId = self::factory()->blog->create();
		$siblingSiteId   = self::factory()->blog->create();
		$activatedIssuer = IssuerIdentity::forSite( $activatedSiteId )->issuer();
		$siblingIssuer   = IssuerIdentity::forSite( $siblingSiteId )->issuer();

		switch_to_blog( $activatedSiteId );
		$activationResult = activate_plugin( plugin_basename( CHARTER_FILE ) );
		restore_current_blog();

		self::assertNull( $activationResult );
		self::assertSame( SiteIssuerLifecycle::PREPARED, SiteIssuerLifecycle::stateFor( $activatedIssuer ) );
		self::assertTrue( SiteIssuerLifecycle::hasIssuer( $activatedIssuer ) );
		self::assertTrue( SiteIssuerLifecycle::publishesDiscoveryFor( $activatedIssuer ) );
		self::assertSame( SiteIssuerLifecycle::AVAILABLE, SiteIssuerLifecycle::stateFor( $siblingIssuer ) );
		self::assertFalse( SiteIssuerLifecycle::hasIssuer( $siblingIssuer ) );
		self::assertFalse( SiteIssuerLifecycle::publishesDiscoveryFor( $siblingIssuer ) );
	}

	/**
	 * Verifies that Network Admin selection prepares only the selected site.
	 *
	 * @since 0.1.0
	 */
	public function testNetworkAdminSelectionPreparesOnlyTheSelectedSite(): void {
		$selectedSiteId = self::factory()->blog->create();
		$siblingSiteId  = self::factory()->blog->create();
		$selectedIssuer = IssuerIdentity::forSite( $selectedSiteId )->issuer();
		$siblingIssuer  = IssuerIdentity::forSite( $siblingSiteId )->issuer();

		$activationResult = activate_plugin(
			plugin_basename( CHARTER_FILE ),
			'',
			true
		);

		self::assertNull( $activationResult );

		NetworkAdminSelection::prepareSite( $selectedSiteId );

		self::assertSame( SiteIssuerLifecycle::PREPARED, SiteIssuerLifecycle::stateFor( $selectedIssuer ) );
		self::assertTrue( SiteIssuerLifecycle::publishesDiscoveryFor( $selectedIssuer ) );
		self::assertSame( SiteIssuerLifecycle::AVAILABLE, SiteIssuerLifecycle::stateFor( $siblingIssuer ) );
		self::assertFalse( SiteIssuerLifecycle::publishesDiscoveryFor( $siblingIssuer ) );
	}

	/**
	 * Verifies that a site created after network activation remains Available.
	 *
	 * @since 0.1.0
	 */
	public function testSiteCreatedAfterNetworkActivationRemainsAvailableWithoutDiscoveryMetadata(): void {
		$activationResult = activate_plugin(
			plugin_basename( CHARTER_FILE ),
			'',
			true
		);

		self::assertNull( $activationResult );

		$newSiteId = self::factory()->blog->create();
		$newIssuer = IssuerIdentity::forSite( $newSiteId )->issuer();

		self::assertSame( SiteIssuerLifecycle::AVAILABLE, SiteIssuerLifecycle::stateFor( $newIssuer ) );
		self::assertFalse( SiteIssuerLifecycle::hasIssuer( $newIssuer ) );
		self::assertFalse( SiteIssuerLifecycle::publishesDiscoveryFor( $newIssuer ) );
	}

	/**
	 * Verifies that one issuer's verification cannot enable a sibling issuer.
	 *
	 * @since 0.1.0
	 */
	public function testRecordedVerificationEnablesOnlyTheExactIssuer(): void {
		$verifiedSiteId = self::factory()->blog->create();
		$siblingSiteId  = self::factory()->blog->create();
		$verifiedIssuer = IssuerIdentity::forSite( $verifiedSiteId )->issuer();
		$siblingIssuer  = IssuerIdentity::forSite( $siblingSiteId )->issuer();

		$activationResult = activate_plugin(
			plugin_basename( CHARTER_FILE ),
			'',
			true
		);

		self::assertNull( $activationResult );

		NetworkAdminSelection::prepareSite( $verifiedSiteId );
		NetworkAdminSelection::prepareSite( $siblingSiteId );

		self::assertTrue( SiteIssuerLifecycle::recordVerification( $verifiedIssuer ) );
		self::assertFalse( SiteIssuerLifecycle::enable( $siblingIssuer ) );
		self::assertSame( SiteIssuerLifecycle::PREPARED, SiteIssuerLifecycle::stateFor( $siblingIssuer ) );
		self::assertTrue( SiteIssuerLifecycle::enable( $verifiedIssuer ) );
		self::assertSame( SiteIssuerLifecycle::ENABLED, SiteIssuerLifecycle::stateFor( $verifiedIssuer ) );
		self::assertSame( SiteIssuerLifecycle::PREPARED, SiteIssuerLifecycle::stateFor( $siblingIssuer ) );
	}
}
