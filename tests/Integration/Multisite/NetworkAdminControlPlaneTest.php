<?php
/**
 * Production Network Admin control over isolated site issuers.
 *
 * @package GalatanOvidiu\Charter
 */

declare(strict_types=1);

namespace GalatanOvidiu\Charter\Tests\Integration\Multisite;

use GalatanOvidiu\Charter\Admin\NetworkAdminPage;
use GalatanOvidiu\Charter\Admin\NetworkSiteControl;
use GalatanOvidiu\Charter\Cli\ContainmentCommand;
use GalatanOvidiu\Charter\Cli\SigningKeyCommand;
use GalatanOvidiu\Charter\OAuth\AuthorizationRequest;
use GalatanOvidiu\Charter\OAuth\Client;
use GalatanOvidiu\Charter\OAuth\CredentialHasher;
use GalatanOvidiu\Charter\OAuth\CredentialStore;
use GalatanOvidiu\Charter\OAuth\EmergencyContainment;
use GalatanOvidiu\Charter\OAuth\GrantRecord;
use GalatanOvidiu\Charter\OAuth\GrantGovernance;
use GalatanOvidiu\Charter\OAuth\SigningKeyLifecycle;
use GalatanOvidiu\Charter\Plugin;
use GalatanOvidiu\Charter\Schema;
use GalatanOvidiu\Charter\Security\AuditEvent;
use GalatanOvidiu\Charter\Site\SiteState;
use RuntimeException;
use WP_UnitTestCase;

/**
 * Verifies selection, lifecycle, capability, confirmation, and table isolation.
 *
 * @since 0.1.0
 */
final class NetworkAdminControlPlaneTest extends WP_UnitTestCase {

	/**
	 * Network plugin state before each test.
	 *
	 * @var array<string, mixed>
	 */
	private array $previousNetworkPlugins = array();

	/**
	 * Every fixture site created while finding unused table prefixes.
	 *
	 * @var array<int>
	 */
	private static array $fixtureSiteIds = array();

	/**
	 * Operable fixture sites whose prefixes had no prior custom tables.
	 *
	 * @var array<int>
	 */
	private static array $operableSiteIds = array();

	/**
	 * Acting network administrator.
	 *
	 * @var int
	 */
	private int $actorUserId;

	/**
	 * HTTPS domain-mapping simulation for production site identity.
	 *
	 * @var \Closure
	 */
	private \Closure $httpsUrlFilter;

	/** Creates sites whose exact prefixes have no stale custom tables. */
	public static function set_up_before_class(): void {
		parent::set_up_before_class();
		foreach ( array( 'selected', 'sibling', 'grants', 'grants-sibling', 'page', 'containment-one', 'containment-two', 'containment-skipped', 'signing-one', 'signing-two' ) as $label ) {
			self::$operableSiteIds[] = self::createFreshFixtureSite( $label );
		}
	}

	/** Deletes the exact class fixture sites after their tables are unused. */
	public static function tear_down_after_class(): void {
		foreach ( self::$fixtureSiteIds as $siteId ) {
			if ( null !== get_site( $siteId ) ) {
				wp_delete_site( $siteId );
			}
		}
		parent::tear_down_after_class();
	}

	/** Enables the production control plane for one isolated test network. */
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

		$this->actorUserId = self::factory()->user->create( array( 'role' => 'administrator' ) );
		grant_super_admin( $this->actorUserId );
		wp_set_current_user( $this->actorUserId );
		$_GET     = array();
		$_POST    = array();
		$_REQUEST = array();
	}

	/** Restores prior network state. */
	public function tear_down(): void {
		remove_filter( 'home_url', $this->httpsUrlFilter );
		remove_filter( 'site_url', $this->httpsUrlFilter );
		update_site_option( 'active_sitewide_plugins', $this->previousNetworkPlugins );
		revoke_super_admin( $this->actorUserId );
		wp_set_current_user( 0 );
		$_GET     = array();
		$_POST    = array();
		$_REQUEST = array();
		parent::tear_down();
	}

	/** Verifies selected preparation and enablement leave a sibling Available. */
	public function testPreparationAndEnablementRemainInsideTheSelectedSite(): void {
		$selectedId = self::$operableSiteIds[0];
		$siblingId  = self::$operableSiteIds[1];
		$control    = $this->control();
		$originBlog = self::currentBlogId();

		$selected = $control->inspect( $selectedId );
		$sibling  = $control->inspect( $siblingId );
		self::assertNotNull( $selected );
		self::assertNotNull( $sibling );
		self::assertSame( SiteState::AVAILABLE, $selected->state() );
		self::assertNull( $selected->identity() );
		self::assertFalse( $selected->storageReady() );
		self::assertSame( SiteState::AVAILABLE, $sibling->state() );
		self::assertNull( $sibling->identity() );
		self::assertFalse( $sibling->storageReady() );

		self::assertTrue( $control->prepare( $selectedId, $this->actorUserId, 1000 ), $this->siteDiagnostics( $selectedId ) );
		$selected = $control->inspect( $selectedId );
		$sibling  = $control->inspect( $siblingId );
		self::assertNotNull( $selected );
		self::assertNotNull( $selected->identity() );
		self::assertSame( SiteState::PREPARED, $selected->state() );
		self::assertTrue( $selected->storageReady() );
		self::assertSame( SiteState::AVAILABLE, $sibling?->state() );
		self::assertNull( $sibling?->identity() );
		self::assertFalse( $sibling?->storageReady() ?? true );
		self::assertSame( $originBlog, self::currentBlogId() );

		$issuer = $selected->identity()->issuer();
		self::assertFalse( $control->enable( $selectedId, $issuer . '/sibling', $this->actorUserId, 1001 ) );
		self::assertTrue( $control->enable( $selectedId, $issuer, $this->actorUserId, 1002 ) );
		$selected = $control->inspect( $selectedId );
		self::assertNotNull( $selected );
		self::assertSame( SiteState::ENABLED, $selected->state() );
		self::assertSame( array( 'site_enabled', 'site_prepared' ), array_map( static fn ( AuditEvent $event ): string => $event->eventType(), $selected->events() ), $this->siteDiagnostics( $selectedId ) );
		self::assertSame( array( 'network_administrator_enablement', 'network_administrator_preparation' ), array_map( static fn ( AuditEvent $event ): string => $event->reason(), $selected->events() ) );
		self::assertSame( $originBlog, self::currentBlogId() );
	}

	/** Verifies network revocation cascades only through the selected site table. */
	public function testGrantRevocationUsesSelectedSiteCredentialsHistoryAndAudit(): void {
		$selectedId     = self::$operableSiteIds[2];
		$siblingId      = self::$operableSiteIds[3];
		$control        = $this->control();
		$selectedIssuer = $this->enableSite( $control, $selectedId, 2000 );
		$siblingIssuer  = $this->enableSite( $control, $siblingId, 2010 );
		$firstUser      = self::factory()->user->create( array( 'role' => 'subscriber' ) );
		$secondUser     = self::factory()->user->create( array( 'role' => 'subscriber' ) );
		$siblingUser    = self::factory()->user->create( array( 'role' => 'subscriber' ) );

		$first   = $this->issueGrant( $selectedId, $selectedIssuer, 'network-first-client', $firstUser );
		$second  = $this->issueGrant( $selectedId, $selectedIssuer, 'network-second-client', $secondUser );
		$sibling = $this->issueGrant( $siblingId, $siblingIssuer, 'network-sibling-client', $siblingUser );
		self::assertSame( $first['grant']->id(), $sibling['grant']->id(), 'The boundary case requires colliding site-local grant identifiers.' );

		$revoked = $control->revokeGrant( $selectedId, $first['grant']->id(), $this->actorUserId, 2020 );
		self::assertInstanceOf( GrantRecord::class, $revoked );
		$selected        = $control->inspect( $selectedId );
		$siblingSnapshot = $control->inspect( $siblingId );
		self::assertNotNull( $selected );
		self::assertNotNull( $siblingSnapshot );
		self::assertSame( 1, $selected->activeGrantCount() );
		self::assertSame( 1, $siblingSnapshot->activeGrantCount() );
		$this->assertCredentialClosed( $selectedId, $selectedIssuer, $first['credential'] );
		$this->assertCredentialActive( $selectedId, $selectedIssuer, $second['credential'] );
		$this->assertCredentialActive( $siblingId, $siblingIssuer, $sibling['credential'] );

		self::assertCount( 1, $control->revokeAllGrants( $selectedId, $this->actorUserId, 2021 ) );
		$selected        = $control->inspect( $selectedId );
		$siblingSnapshot = $control->inspect( $siblingId );
		self::assertSame( 0, $selected?->activeGrantCount() );
		self::assertSame( 1, $siblingSnapshot?->activeGrantCount() );
		$this->assertCredentialClosed( $selectedId, $selectedIssuer, $second['credential'] );
		$this->assertCredentialActive( $siblingId, $siblingIssuer, $sibling['credential'] );

		$selectedReasons = array_map( static fn ( AuditEvent $event ): string => $event->reason(), $selected?->events() ?? array() );
		self::assertContains( 'network_administrator_grant_revocation', $selectedReasons );
		self::assertContains( 'network_administrator_site_revocation', $selectedReasons );
		$siblingReasons = array_map( static fn ( AuditEvent $event ): string => $event->reason(), $siblingSnapshot?->events() ?? array() );
		self::assertNotContains( 'network_administrator_grant_revocation', $siblingReasons );
		self::assertNotContains( 'network_administrator_site_revocation', $siblingReasons );

		switch_to_blog( $selectedId );
		try {
			$history = Plugin::boot()->credentials()->listRecentRevokedGrantsForUser( $selectedIssuer, $firstUser, 0 );
			self::assertCount( 1, $history );
			self::assertSame( 'network_administrator_grant_revocation', $history[0]->revocationReason() );
		} finally {
			restore_current_blog();
		}
	}

	/** Verifies the page requires network authority, exact nonces, and confirmation. */
	public function testPageAndMutationsAreNetworkCapabilityNonceAndConfirmationBound(): void {
		$siteId  = self::$operableSiteIds[4];
		$control = $this->control();
		$page    = new NetworkAdminPage( $control );
		$_GET    = array( 'site_id' => (string) $siteId );

		ob_start();
		$page->render();
		$html        = (string) ob_get_clean();
		$nonceAction = self::nonceAction( 'charter_oauth_network_prepare_site', (string) $siteId );
		self::assertStringContainsString( 'Charter OAuth network control', $html );
		self::assertStringContainsString( 'OAuth state: Available', $html );
		self::assertStringContainsString( 'network/edit.php?action=charter_oauth_network_prepare_site', $html );
		self::assertStringContainsString( wp_create_nonce( $nonceAction ), $html );
		self::assertStringContainsString( 'name="confirm_action"', $html );
		self::assertStringContainsString( 'does not create network clients, grants, credentials, or an OAuth issuer', $html );

		$siteAdministrator = self::factory()->user->create( array( 'role' => 'administrator' ) );
		wp_set_current_user( $siteAdministrator );
		$this->withDieHandler( static fn () => $page->render(), 'not allowed to manage Charter OAuth for this network' );

		wp_set_current_user( $this->actorUserId );
		$_POST    = array(
			'site_id'  => (string) $siteId,
			'_wpnonce' => 'invalid-nonce',
		);
		$_REQUEST = $_POST; // phpcs:ignore WordPress.Security.NonceVerification.Missing -- Test synchronizes the request before the production handler verifies it.
		$this->withDieHandler( static fn () => $page->prepareSite(), 'link you followed has expired' );

		$_POST    = array(
			'site_id'  => (string) $siteId,
			'_wpnonce' => wp_create_nonce( $nonceAction ),
		);
		$_REQUEST = $_POST; // phpcs:ignore WordPress.Security.NonceVerification.Missing -- Test synchronizes the request before the production handler verifies it.
		$this->withDieHandler( static fn () => $page->prepareSite(), 'selected site could not be prepared' );
		self::assertSame( SiteState::AVAILABLE, $control->inspect( $siteId )?->state() );

		update_site_option( 'active_sitewide_plugins', $this->previousNetworkPlugins );
		self::assertNull( $control->inspect( $siteId ) );
		self::assertFalse( $control->prepare( $siteId, $this->actorUserId, 3000 ) );
	}

	/** Verifies selected, all-site, and CLI transitions stay issuer-local and reversible. */
	public function testEmergencyContainmentOrchestrationIsSequentialAndSiteIsolated(): void {
		$firstId      = self::$operableSiteIds[5];
		$secondId     = self::$operableSiteIds[6];
		$skippedId    = self::$operableSiteIds[7];
		$control      = $this->control();
		$originBlog   = self::currentBlogId();
		$firstIssuer  = $this->enableSite( $control, $firstId, 4000 );
		$secondIssuer = $this->enableSite( $control, $secondId, 4010 );
		$firstUser    = self::factory()->user->create( array( 'role' => 'subscriber' ) );
		$secondUser   = self::factory()->user->create( array( 'role' => 'subscriber' ) );
		$firstGrant   = $this->issueGrant( $firstId, $firstIssuer, 'containment-first-client', $firstUser );
		$secondGrant  = $this->issueGrant( $secondId, $secondIssuer, 'containment-second-client', $secondUser );
		$page         = new NetworkAdminPage( $control );
		$nonceAction  = self::nonceAction( 'charter_oauth_network_set_containment', (string) get_current_network_id(), 'site', (string) $firstId, $firstIssuer, EmergencyContainment::ISSUANCE_PAUSED );
		$_POST        = array(
			'scope'    => 'site',
			'mode'     => EmergencyContainment::ISSUANCE_PAUSED,
			'site_id'  => (string) $firstId,
			'issuer'   => $firstIssuer,
			'_wpnonce' => wp_create_nonce( $nonceAction ),
		);
		$_REQUEST     = $_POST; // phpcs:ignore WordPress.Security.NonceVerification.Missing -- Test synchronizes the request before the production handler verifies it.
		$this->withDieHandler( static fn () => $page->setContainment(), 'emergency containment request is invalid' );
		self::assertSame( EmergencyContainment::RESUMED, $control->inspect( $firstId )?->containmentMode() );

		self::assertFalse( $control->transitionContainment( $firstId, $secondIssuer, EmergencyContainment::ISSUANCE_PAUSED, $this->actorUserId, 4020 ) );
		self::assertTrue( $control->transitionContainment( $firstId, $firstIssuer, EmergencyContainment::ISSUANCE_PAUSED, $this->actorUserId, 4021 ) );
		self::assertSame( EmergencyContainment::ISSUANCE_PAUSED, $control->inspect( $firstId )?->containmentMode() );
		self::assertSame( EmergencyContainment::RESUMED, $control->inspect( $secondId )?->containmentMode() );
		self::assertSame( SiteState::AVAILABLE, $control->inspect( $skippedId )?->state() );
		self::assertSame( $originBlog, self::currentBlogId() );
		$this->assertCredentialActive( $firstId, $firstIssuer, $firstGrant['credential'] );
		$this->assertCredentialActive( $secondId, $secondIssuer, $secondGrant['credential'] );

		$allLocked = $control->transitionAllContainment( EmergencyContainment::LOCKDOWN, $this->actorUserId, 4022 );
		self::assertGreaterThanOrEqual( 2, $allLocked['changed'] );
		self::assertGreaterThanOrEqual( 1, $allLocked['skipped'] );
		self::assertSame( 0, $allLocked['pending'] );
		self::assertSame( 0, $allLocked['failed'] );
		self::assertSame( EmergencyContainment::LOCKDOWN, $control->inspect( $firstId )?->containmentMode() );
		self::assertSame( EmergencyContainment::LOCKDOWN, $control->inspect( $secondId )?->containmentMode() );
		self::assertSame( SiteState::AVAILABLE, $control->inspect( $skippedId )?->state() );
		self::assertSame( $originBlog, self::currentBlogId() );
		$this->assertCredentialActive( $firstId, $firstIssuer, $firstGrant['credential'] );
		$this->assertCredentialActive( $secondId, $secondIssuer, $secondGrant['credential'] );

		$plugin         = Plugin::boot();
		$command        = new ContainmentCommand( $plugin->containment(), $plugin->siteState() );
		$selectedResume = $command->transitionSites( array( $secondId, $firstId ), EmergencyContainment::RESUMED, 4023 );
		self::assertSame( array( $secondId, $firstId ), array_keys( $selectedResume ) );
		self::assertTrue( $selectedResume[ $secondId ]['changed'] ?? false );
		self::assertTrue( $selectedResume[ $firstId ]['changed'] ?? false );
		self::assertFalse( $selectedResume[ $secondId ]['audit_pending'] ?? true );
		self::assertFalse( $selectedResume[ $firstId ]['audit_pending'] ?? true );
		$status = $command->statusForSites( array( $firstId, $secondId ) );
		self::assertSame( EmergencyContainment::RESUMED, $status[ $firstId ]['mode'] ?? null );
		self::assertSame( EmergencyContainment::RESUMED, $status[ $secondId ]['mode'] ?? null );
		self::assertSame( $originBlog, self::currentBlogId() );

		$firstSnapshot  = $control->inspect( $firstId );
		$secondSnapshot = $control->inspect( $secondId );
		self::assertNotNull( $firstSnapshot );
		self::assertNotNull( $secondSnapshot );
		$firstReasons  = array_map( static fn ( AuditEvent $event ): string => $event->reason(), $firstSnapshot->events() );
		$secondReasons = array_map( static fn ( AuditEvent $event ): string => $event->reason(), $secondSnapshot->events() );
		self::assertContains( 'network_administrator_issuance_paused', $firstReasons );
		self::assertContains( 'network_administrator_lockdown', $firstReasons );
		self::assertContains( 'wp_cli_resumed', $firstReasons );
		self::assertNotContains( 'network_administrator_issuance_paused', $secondReasons, 'The first selected-site transition must not reach the sibling issuer.' );
		self::assertContains( 'network_administrator_lockdown', $secondReasons );
		self::assertContains( 'wp_cli_resumed', $secondReasons );
		$this->assertCredentialActive( $firstId, $firstIssuer, $firstGrant['credential'] );
		$this->assertCredentialActive( $secondId, $secondIssuer, $secondGrant['credential'] );
	}

	/** Verifies explicit-key Network Admin batches and WP-CLI remain issuer-local. */
	public function testSigningKeyOrchestrationIsExactSequentialAndSiteIsolated(): void {
		$firstId      = self::$operableSiteIds[8];
		$secondId     = self::$operableSiteIds[9];
		$originBlog   = self::currentBlogId();
		$keyPhase     = 'a';
		$plugin       = Plugin::boot();
		$signingKeys  = new SigningKeyLifecycle(
			$plugin->siteState(),
			$plugin->audit(),
			static function () use ( &$keyPhase ): array {
				return array(
					'source'            => SigningKeyLifecycle::SOURCE_EXPLICIT,
					'root'              => hash( 'sha256', 'charter-multisite-explicit-key:' . $keyPhase ),
					'database_fallback' => false,
				);
			}
		);
		$credentials  = new CredentialStore( new CredentialHasher( $signingKeys ) );
		$control      = new NetworkSiteControl( $plugin->siteState(), $credentials, new GrantGovernance( $credentials, $plugin->audit() ), $plugin->audit(), $plugin->containment(), $signingKeys );
		$firstIssuer  = $this->enableSite( $control, $firstId, 5000 );
		$secondIssuer = $this->enableSite( $control, $secondId, 5010 );
		self::assertSame( SigningKeyLifecycle::STATUS_MATCHING, $control->inspect( $firstId )?->signingKeyStatus() );
		self::assertSame( SigningKeyLifecycle::STATUS_MATCHING, $control->inspect( $secondId )?->signingKeyStatus() );

		$keyPhase       = 'b';
		$firstMismatch  = $control->inspect( $firstId );
		$secondMismatch = $control->inspect( $secondId );
		self::assertNotNull( $firstMismatch );
		self::assertNotNull( $secondMismatch );
		self::assertSame( SigningKeyLifecycle::STATUS_MISMATCH, $firstMismatch->signingKeyStatus() );
		self::assertSame( SigningKeyLifecycle::STATUS_MISMATCH, $secondMismatch->signingKeyStatus() );
		self::assertSame( 0, $secondMismatch->signingKeyGeneration() );
		$mismatchId = $firstMismatch->signingKeyMismatchId();
		self::assertIsString( $mismatchId );
		self::assertFalse( $control->adoptSigningKey( $firstId, $secondIssuer, $mismatchId, $this->actorUserId, 5020 ) );
		self::assertSame( $originBlog, self::currentBlogId() );

		$page        = new NetworkAdminPage( $control );
		$_GET        = array( 'site_id' => (string) $firstId );
		$nonceAction = self::nonceAction( 'charter_oauth_network_adopt_signing_key', (string) get_current_network_id(), 'site', (string) $firstId, $firstIssuer, $mismatchId );
		ob_start();
		$page->render();
		$html = (string) ob_get_clean();
		self::assertStringContainsString( 'Signing key: source explicit; status mismatch', $html );
		self::assertStringContainsString( wp_create_nonce( $nonceAction ), $html );
		self::assertStringContainsString( 'name="confirm_action"', $html );

		$_POST    = array(
			'scope'          => 'site',
			'site_id'        => (string) $firstId,
			'issuer'         => $firstIssuer,
			'binding_id'     => $mismatchId,
			'confirm_action' => '1',
			'_wpnonce'       => 'invalid-nonce',
		);
		$_REQUEST = $_POST; // phpcs:ignore WordPress.Security.NonceVerification.Missing -- The production handler verifies the synchronized request.
		$this->withDieHandler( static fn () => $page->adoptSigningKey(), 'link you followed has expired' );

		$_POST    = array(
			'scope'      => 'site',
			'site_id'    => (string) $firstId,
			'issuer'     => $firstIssuer,
			'binding_id' => $mismatchId,
			'_wpnonce'   => wp_create_nonce( $nonceAction ),
		);
		$_REQUEST = $_POST; // phpcs:ignore WordPress.Security.NonceVerification.Missing -- The production handler verifies the synchronized request.
		$this->withDieHandler( static fn () => $page->adoptSigningKey(), 'adoption request is invalid' );
		self::assertTrue( $control->adoptSigningKey( $firstId, $firstIssuer, $mismatchId, $this->actorUserId, 5021 ) );
		self::assertSame( SigningKeyLifecycle::STATUS_MATCHING, $control->inspect( $firstId )?->signingKeyStatus() );
		self::assertSame( SigningKeyLifecycle::STATUS_MISMATCH, $control->inspect( $secondId )?->signingKeyStatus() );
		self::assertSame( 1, $control->inspect( $firstId )?->signingKeyGeneration() );
		self::assertSame( 0, $control->inspect( $secondId )?->signingKeyGeneration() );
		self::assertSame( $originBlog, self::currentBlogId() );

		$keyPhase   = 'c';
		$staleBatch = $control->signingKeyBatch();
		self::assertSame( 2, $staleBatch['actionable'] );
		$keyPhase = 'd';
		self::assertSame( 1, $control->adoptAllSigningKeys( $staleBatch['batch_id'], $this->actorUserId, 5030 )['failed'] );
		self::assertSame( 1, $control->inspect( $firstId )?->signingKeyGeneration() );
		self::assertSame( 0, $control->inspect( $secondId )?->signingKeyGeneration() );

		$currentBatch = $control->signingKeyBatch();
		$batchResult  = $control->adoptAllSigningKeys( $currentBatch['batch_id'], $this->actorUserId, 5031 );
		self::assertSame( 2, $batchResult['changed'] );
		self::assertSame( 0, $batchResult['pending'] );
		self::assertSame( 0, $batchResult['failed'] );
		self::assertSame( 2, $control->inspect( $firstId )?->signingKeyGeneration() );
		self::assertSame( 1, $control->inspect( $secondId )?->signingKeyGeneration() );
		self::assertSame( $originBlog, self::currentBlogId() );

		$keyPhase = 'e';
		$command  = new SigningKeyCommand( $signingKeys, $plugin->siteState() );
		$status   = $command->statusForSites( array( $secondId, $firstId ) );
		self::assertSame( array( $secondId, $firstId ), array_keys( $status ) );
		self::assertSame( SigningKeyLifecycle::STATUS_MISMATCH, $status[ $firstId ]['status'] ?? null );
		self::assertSame( SigningKeyLifecycle::STATUS_MISMATCH, $status[ $secondId ]['status'] ?? null );
		$cliResult = $command->adoptForSites( array( $secondId, $firstId ), 5040 );
		self::assertTrue( $cliResult[ $firstId ]['adopted'] ?? false );
		self::assertTrue( $cliResult[ $secondId ]['adopted'] ?? false );
		self::assertSame( 3, $cliResult[ $firstId ]['generation'] ?? null );
		self::assertSame( 2, $cliResult[ $secondId ]['generation'] ?? null );
		$afterCli = $command->statusForSites( array( $firstId, $secondId ) );
		self::assertSame( SigningKeyLifecycle::ACTOR_WP_CLI, $afterCli[ $firstId ]['actor'] ?? null );
		self::assertSame( SigningKeyLifecycle::ACTOR_WP_CLI, $afterCli[ $secondId ]['actor'] ?? null );
		self::assertSame( $originBlog, self::currentBlogId() );
	}

	/** Returns the production network service composed over current-site services. */
	private function control(): NetworkSiteControl {
		$plugin = Plugin::boot();

		return new NetworkSiteControl( $plugin->siteState(), $plugin->credentials(), $plugin->grantGovernance(), $plugin->audit(), $plugin->containment(), $plugin->signingKeys() );
	}

	/**
	 * Creates one site whose prefix has no stale Charter custom tables.
	 *
	 * WordPress's test bootstrap recreates Core tables while deliberately leaving
	 * plugin custom tables outside its transaction. Skipping occupied prefixes
	 * avoids destructive DDL and keeps each class fixture exact.
	 *
	 * @param string $label Stable fixture label.
	 * @throws RuntimeException When no fresh prefix can be allocated safely.
	 */
	private static function createFreshFixtureSite( string $label ): int {
		global $wpdb;

		$rows   = $wpdb->get_col( 'SHOW TABLES' ); // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching -- Read-only allocation avoids stale custom-table prefixes in the test database.
		$tables = array_values( array_filter( $rows, 'is_string' ) );
		for ( $attempt = 1; $attempt <= 200; ++$attempt ) {
			$domain                 = sprintf( 'network-%s-%d.example.org', $label, $attempt );
			$siteId                 = self::factory()->blog->create(
				array(
					'domain' => $domain,
					'path'   => '/',
				)
			);
			self::$fixtureSiteIds[] = $siteId;
			$prefix                 = $wpdb->get_blog_prefix( $siteId );
			$occupied               = false;
			foreach ( array( 'credentials', 'grants', 'clients', 'rate_limits', 'audit', 'cimd_cache' ) as $suffix ) {
				if ( in_array( $prefix . 'charter_oauth_' . $suffix, $tables, true ) ) {
					$occupied = true;
					break;
				}
			}
			if ( ! $occupied ) {
				switch_to_blog( $siteId );
				try {
					Schema::install();
				} finally {
					restore_current_blog();
				}
				delete_blog_option( $siteId, 'charter_oauth_schema_version' );
				delete_blog_option( $siteId, 'charter_oauth_site_state' );

				return $siteId;
			}
		}

		throw new RuntimeException( 'Fresh fixture table prefix unavailable.' );
	}

	/**
	 * Prepares and enables one selected site.
	 *
	 * @param NetworkSiteControl $control Production network control.
	 * @param int                $siteId Selected site identifier.
	 * @param int                $timestamp Initial timestamp.
	 */
	private function enableSite( NetworkSiteControl $control, int $siteId, int $timestamp ): string {
		self::assertTrue( $control->prepare( $siteId, $this->actorUserId, $timestamp ), $this->siteDiagnostics( $siteId ) );
		$snapshot = $control->inspect( $siteId );
		self::assertNotNull( $snapshot?->identity() );
		$issuer = $snapshot->identity()->issuer();
		self::assertTrue( $control->enable( $siteId, $issuer, $this->actorUserId, $timestamp + 1 ) );

		return $issuer;
	}

	/**
	 * Issues one grant and returns its non-output credential fixture.
	 *
	 * @param int    $siteId Selected site identifier.
	 * @param string $issuer Exact selected issuer.
	 * @param string $clientId Test client identifier.
	 * @param int    $userId Represented user identifier.
	 * @return array{grant:GrantRecord,credential:string}
	 */
	private function issueGrant( int $siteId, string $issuer, string $clientId, int $userId ): array {
		switch_to_blog( $siteId );
		try {
			$store       = Plugin::boot()->credentials();
			$client      = new Client( $issuer, $clientId, $clientId, array( 'https://' . $clientId . '.example.test/callback' ) );
			$request     = new AuthorizationRequest( $issuer, $issuer, $client, $client->redirectUris()[0], 'wordpress:access', str_repeat( 'a', 43 ), null ); // phpcs:ignore WordPress.WP.CapitalPDangit.MisspelledInText -- Exact OAuth scope token.
			$transaction = $store->issueAuthorizationRequest( $request, $userId, 2015 );
			$record      = $store->find( CredentialStore::AUTHORIZATION_REQUEST, $issuer, $transaction );
			self::assertNotNull( $record );
			$credential = $store->approveAuthorization( $record, 2016 );
			self::assertIsString( $credential );
			$grants = $store->listActiveGrantsForUser( $issuer, $userId );
			self::assertCount( 1, $grants );

			return array(
				'grant'      => $grants[0],
				'credential' => $credential,
			);
		} finally {
			restore_current_blog();
		}
	}

	/**
	 * Confirms one descendant credential is closed in the selected table.
	 *
	 * @param int    $siteId Selected site identifier.
	 * @param string $issuer Exact selected site issuer.
	 * @param string $credential Non-output test credential.
	 */
	private function assertCredentialClosed( int $siteId, string $issuer, string $credential ): void {
		switch_to_blog( $siteId );
		try {
			$record = Plugin::boot()->credentials()->find( CredentialStore::AUTHORIZATION_CODE, $issuer, $credential );
			self::assertNotNull( $record );
			self::assertNotNull( $record->consumedAt() );
		} finally {
			restore_current_blog();
		}
	}

	/**
	 * Confirms one descendant credential remains active in the selected table.
	 *
	 * @param int    $siteId Selected site identifier.
	 * @param string $issuer Exact selected site issuer.
	 * @param string $credential Non-output test credential.
	 */
	private function assertCredentialActive( int $siteId, string $issuer, string $credential ): void {
		switch_to_blog( $siteId );
		try {
			$record = Plugin::boot()->credentials()->find( CredentialStore::AUTHORIZATION_CODE, $issuer, $credential );
			self::assertNotNull( $record );
			self::assertNull( $record->consumedAt() );
		} finally {
			restore_current_blog();
		}
	}

	/**
	 * Returns bounded non-secret site-state diagnostics for a failed transition.
	 *
	 * @param int $siteId Selected site identifier.
	 */
	private function siteDiagnostics( int $siteId ): string {
		global $wpdb;

		$requestedPrefix = $wpdb->get_blog_prefix( $siteId );
		switch_to_blog( $siteId );
		try {
			return (string) wp_json_encode(
				array(
					'home'             => get_option( 'home' ),
					'siteurl'          => get_option( 'siteurl' ),
					'state'            => get_option( 'charter_oauth_site_state', array() ),
					'requested_prefix' => $requestedPrefix,
					'current_prefix'   => $wpdb->prefix,
				)
			);
		} finally {
			restore_current_blog();
		}
	}

	/** Returns the current WordPress site locator without constructing identity. */
	private static function currentBlogId(): int {
		global $blog_id;

		return (int) $blog_id;
	}

	/**
	 * Returns the exact production-compatible form nonce action.
	 *
	 * @param string $action Fixed Network Admin action.
	 * @param string ...$bindings Exact selected-site bindings.
	 */
	private static function nonceAction( string $action, string ...$bindings ): string {
		return $action . ':' . hash( 'sha256', implode( "\0", $bindings ) );
	}

	/**
	 * Runs one expected WordPress termination through a deterministic handler.
	 *
	 * @param callable $callback Protected operation expected to stop.
	 * @param string   $expectedMessage Expected non-secret message fragment.
	 */
	private function withDieHandler( callable $callback, string $expectedMessage ): void {
		$filter = static function (): callable {
			return static function ( mixed $message ): never {
				$text = is_string( $message ) ? wp_strip_all_tags( $message ) : '';
				throw new RuntimeException( $text ); // phpcs:ignore WordPress.Security.EscapeOutput.ExceptionNotEscaped -- Test-only control flow; the exception is never rendered.
			};
		};
		add_filter( 'wp_die_handler', $filter );
		try {
			$callback();
			self::fail( 'The protected Network Admin action did not stop.' );
		} catch ( RuntimeException $exception ) {
			self::assertStringContainsString( $expectedMessage, $exception->getMessage() );
		} finally {
			remove_filter( 'wp_die_handler', $filter );
		}
	}
}
