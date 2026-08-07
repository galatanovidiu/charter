<?php
/**
 * Site-administrator grant governance integration tests.
 *
 * @package GalatanOvidiu\Charter
 */

declare(strict_types=1);

namespace GalatanOvidiu\Charter\Tests\Integration\OAuth;

use GalatanOvidiu\Charter\Admin\ConnectedAppsPage;
use GalatanOvidiu\Charter\Admin\SettingsPage;
use GalatanOvidiu\Charter\OAuth\AuthorizationService;
use GalatanOvidiu\Charter\OAuth\Client;
use GalatanOvidiu\Charter\OAuth\EmergencyContainment;
use GalatanOvidiu\Charter\OAuth\GrantRecord;
use GalatanOvidiu\Charter\OAuth\ProtocolException;
use GalatanOvidiu\Charter\OAuth\TokenService;
use GalatanOvidiu\Charter\Plugin;
use GalatanOvidiu\Charter\Schema;
use GalatanOvidiu\Charter\Security\AuditEvent;
use RuntimeException;
use WP_UnitTestCase;

/**
 * Exercises site-wide visibility, exact revocation boundaries, and user notice.
 *
 * @since 0.1.0
 */
final class SiteAdministratorGrantGovernanceTest extends WP_UnitTestCase {

	private const CLIENT_ONE = 'admin-governance-one';
	private const CLIENT_TWO = 'admin-governance-two';
	private const REDIRECT   = 'https://administrator-governance.example.test/callback';
	private const VERIFIER   = '0123456789abcdefghijklmnopqrstuvwxyzABCDEFG';

	/**
	 * Exact current site issuer.
	 *
	 * @var string
	 */
	private string $issuer;

	/** Installs the current schema before Core test transactions. */
	public static function set_up_before_class(): void {
		parent::set_up_before_class();
		Schema::install();
	}

	/** Creates one isolated enabled site issuer. */
	public function set_up(): void {
		parent::set_up();
		$plugin = Plugin::boot();
		Schema::install();
		$plugin->credentials()->deleteAll();
		$plugin->clients()->deleteAll();
		$plugin->clientMetadataSnapshots()->deleteAll();
		$plugin->audit()->deleteAll();
		$plugin->rateLimiter()->deleteAll();
		$plugin->containment()->delete();
		$plugin->siteState()->delete();
		self::assertTrue( $plugin->siteState()->prepareCurrentSite() );
		$identity = $plugin->siteState()->identity();
		self::assertNotNull( $identity );
		$this->issuer = $identity->issuer();
		self::assertTrue( $plugin->siteState()->recordDiscoveryVerification( $this->issuer ) );
		self::assertTrue( $plugin->siteState()->enable( $this->issuer ) );
		self::assertTrue( $plugin->clients()->registerPublicClient( $this->issuer, self::CLIENT_ONE, 'Governance One', array( self::REDIRECT ), true ) );
		self::assertTrue( $plugin->clients()->registerPublicClient( $this->issuer, self::CLIENT_TWO, 'Governance Two', array( self::REDIRECT ), true ) );
		$_GET     = array();
		$_POST    = array();
		$_REQUEST = array();
	}

	/** Removes current-site fixture state. */
	public function tear_down(): void {
		$plugin = Plugin::boot();
		$plugin->credentials()->deleteAll();
		$plugin->clients()->deleteAll();
		$plugin->clientMetadataSnapshots()->deleteAll();
		$plugin->audit()->deleteAll();
		$plugin->rateLimiter()->deleteAll();
		$plugin->containment()->delete();
		$plugin->siteState()->delete();
		$_GET     = array();
		$_POST    = array();
		$_REQUEST = array();
		wp_set_current_user( 0 );
		parent::tear_down();
	}

	/** Verifies one action cannot cross issuer, user, client, or grant boundaries. */
	public function testIndividualRevocationClosesOnlyExactGrantAndEmitsSecretFreeAudit(): void {
		$plugin    = Plugin::boot();
		$actorId   = self::factory()->user->create( array( 'role' => 'administrator' ) );
		$firstUser = self::factory()->user->create( array( 'role' => 'subscriber' ) );
		$otherUser = self::factory()->user->create( array( 'role' => 'subscriber' ) );
		$first     = $this->issueTokens( self::CLIENT_ONE, $firstUser );
		$other     = $this->issueTokens( self::CLIENT_ONE, $otherUser );
		$events    = array();
		$listener  = static function ( AuditEvent $event ) use ( &$events ): void {
			$events[] = $event;
		};
		add_action( 'charter_oauth_audit_event_recorded', $listener );

		try {
			self::assertNull( $plugin->grantGovernance()->revoke( $this->issuer . '/sibling', $first['grant']->id(), $actorId, time() ) );
			self::assertNull( $plugin->grantGovernance()->revoke( $this->issuer, $first['grant']->id(), 0, time() ) );
			self::assertCount( 1, $plugin->credentials()->listActiveGrantsForUser( $this->issuer, $firstUser ) );

			$revoked = $plugin->grantGovernance()->revoke( $this->issuer, $first['grant']->id(), $actorId, time() );
			self::assertInstanceOf( GrantRecord::class, $revoked );
		} finally {
			remove_action( 'charter_oauth_audit_event_recorded', $listener );
		}

		self::assertSame( array(), $plugin->credentials()->listActiveGrantsForUser( $this->issuer, $firstUser ) );
		self::assertCount( 1, $plugin->credentials()->listActiveGrantsForUser( $this->issuer, $otherUser ) );
		$this->assertTokenRejected( $first['access_token'] );
		self::assertSame( $otherUser, $plugin->tokens()->validateAccessToken( $other['access_token'], $this->issuer, array( AuthorizationService::GENERAL_SCOPE ) )->userId() );

		$ledger = $plugin->audit()->listForIssuer( $this->issuer );
		self::assertCount( 1, $ledger );
		self::assertCount( 1, $events );
		foreach ( array( $ledger[0], $events[0] ) as $event ) {
			self::assertSame( $this->issuer, $event->issuer() );
			self::assertSame( 'grant_revoked', $event->eventType() );
			self::assertSame( 'administrator_grant_revocation', $event->reason() );
			self::assertSame( $actorId, $event->actorUserId() );
			self::assertSame( $firstUser, $event->representedUserId() );
			self::assertSame( self::CLIENT_ONE, $event->clientId() );
			self::assertSame( $this->issuer, $event->resource() );
			self::assertSame( AuthorizationService::GENERAL_SCOPE, $event->scopes() );
			$projection = implode( '|', array_filter( array( $event->issuer(), $event->eventType(), $event->reason(), $event->clientId(), $event->resource(), $event->scopes() ), 'is_string' ) );
			self::assertStringNotContainsString( $first['access_token'], $projection );
			self::assertStringNotContainsString( $first['refresh_token'], $projection );
		}
	}

	/** Verifies explicit site-wide revocation is complete and keeps clients usable. */
	public function testSiteWideRevocationClosesAllGrantsWithoutDeletingClients(): void {
		$plugin  = Plugin::boot();
		$actorId = self::factory()->user->create( array( 'role' => 'administrator' ) );
		$first   = $this->issueTokens( self::CLIENT_ONE, self::factory()->user->create( array( 'role' => 'subscriber' ) ) );
		$second  = $this->issueTokens( self::CLIENT_TWO, self::factory()->user->create( array( 'role' => 'subscriber' ) ) );

		self::assertSame( array(), $plugin->grantGovernance()->revokeAll( $this->issuer . '/sibling', $actorId, time() ) );
		self::assertSame( 2, $plugin->credentials()->countActiveGrantsForIssuer( $this->issuer ) );
		self::assertCount( 2, $plugin->grantGovernance()->revokeAll( $this->issuer, $actorId, time() ) );
		self::assertSame( 0, $plugin->credentials()->countActiveGrantsForIssuer( $this->issuer ) );
		$this->assertTokenRejected( $first['access_token'] );
		$this->assertTokenRejected( $second['access_token'] );
		self::assertNotNull( $plugin->clients()->findActive( $this->issuer, self::CLIENT_ONE ) );
		self::assertNotNull( $plugin->clients()->findActive( $this->issuer, self::CLIENT_TWO ) );

		$events = $plugin->audit()->listForIssuer( $this->issuer );
		self::assertCount( 1, $events );
		self::assertSame( 'site_grants_revoked', $events[0]->eventType() );
		self::assertSame( 'administrator_site_revocation', $events[0]->reason() );
		self::assertNull( $events[0]->representedUserId() );
		self::assertNull( $events[0]->clientId() );
	}

	/** Verifies the administrator screen exposes details and exact nonce contracts. */
	public function testSettingsInventoryIsCapabilityAndNonceBoundWithoutCredentialDisclosure(): void {
		$plugin    = Plugin::boot();
		$actorId   = self::factory()->user->create(
			array(
				'role'         => 'administrator',
				'display_name' => 'Site Operator',
			)
		);
		$firstUser = self::factory()->user->create(
			array(
				'role'         => 'subscriber',
				'display_name' => 'First Represented User',
			)
		);
		$otherUser = self::factory()->user->create(
			array(
				'role'         => 'subscriber',
				'display_name' => 'Second Represented User',
			)
		);
		$first     = $this->issueTokens( self::CLIENT_ONE, $firstUser );
		$other     = $this->issueTokens( self::CLIENT_TWO, $otherUser );
		$page      = $this->settingsPage();
		wp_set_current_user( $actorId );

		ob_start();
		$page->render();
		$html = (string) ob_get_clean();
		self::assertStringContainsString( 'id="charter-site-admin-root"', $html );
		self::assertStringContainsString( 'id="charter-site-admin-data"', $html );
		self::assertStringContainsString( 'Site authorizations', $html );
		self::assertStringContainsString( 'First Represented User', $html );
		self::assertStringContainsString( 'Second Represented User', $html );
		self::assertStringContainsString( 'Governance One', $html );
		self::assertStringContainsString( 'Governance Two', $html );
		self::assertStringContainsString( 'Resource: ' . $this->issuer, $html );
		self::assertStringContainsString( 'Scopes: wordpress:access', $html ); // phpcs:ignore WordPress.WP.CapitalPDangit.MisspelledInText -- Exact OAuth scope token.
		self::assertStringContainsString( 'Continuing access: Yes', $html );
		self::assertStringContainsString( 'charter_oauth_revoke_site_grant', $html );
		self::assertStringContainsString( 'charter_oauth_revoke_all_site_grants', $html );
		self::assertStringContainsString( 'Emergency containment', $html );
		self::assertStringContainsString( 'Mode: resumed', $html );
		self::assertStringContainsString( wp_create_nonce( 'charter_oauth_revoke_site_grant:' . hash( 'sha256', $this->issuer . "\0" . $first['grant']->id() ) ), $html );
		self::assertStringContainsString( wp_create_nonce( 'charter_oauth_revoke_all_site_grants:' . hash( 'sha256', $this->issuer ) ), $html );
		$containmentNonce = wp_create_nonce( 'charter_oauth_set_emergency_mode:' . hash( 'sha256', $this->issuer . "\0" . EmergencyContainment::ISSUANCE_PAUSED ) );
		self::assertStringContainsString( $containmentNonce, $html );
		self::assertStringNotContainsString( $first['access_token'], $html );
		self::assertStringNotContainsString( $first['refresh_token'], $html );
		self::assertStringNotContainsString( $other['access_token'], $html );

		$subscriberId = self::factory()->user->create( array( 'role' => 'subscriber' ) );
		wp_set_current_user( $subscriberId );
		$this->withDieHandler(
			static function () use ( $page ): void {
				$page->render();
			},
			'not allowed to manage Charter OAuth'
		);

		wp_set_current_user( $actorId );
		$_POST    = array(
			'action'         => 'charter_oauth_set_emergency_mode',
			'mode'           => EmergencyContainment::ISSUANCE_PAUSED,
			'confirm_action' => '1',
			'_wpnonce'       => 'invalid-nonce',
		);
		$_REQUEST = $_POST; // phpcs:ignore WordPress.Security.NonceVerification.Missing -- Test synchronizes request superglobals before the production handler verifies the nonce.
		$this->withDieHandler(
			static function () use ( $page ): void {
				$page->setContainmentMode();
			},
			'link you followed has expired'
		);

		$_POST    = array(
			'action'   => 'charter_oauth_set_emergency_mode',
			'mode'     => EmergencyContainment::ISSUANCE_PAUSED,
			'_wpnonce' => $containmentNonce,
		);
		$_REQUEST = $_POST; // phpcs:ignore WordPress.Security.NonceVerification.Missing -- Test synchronizes request superglobals before the production handler verifies the nonce.
		$this->withDieHandler(
			static function () use ( $page ): void {
				$page->setContainmentMode();
			},
			'emergency mode could not be changed'
		);
		self::assertSame( EmergencyContainment::RESUMED, $plugin->containment()->mode() );

		$_POST    = array(
			'action'   => 'charter_oauth_revoke_site_grant',
			'grant_id' => (string) $first['grant']->id(),
			'_wpnonce' => 'invalid-nonce',
		);
		$_REQUEST = $_POST; // phpcs:ignore WordPress.Security.NonceVerification.Missing -- Test synchronizes request superglobals before the production handler verifies the nonce.
		$this->withDieHandler(
			static function () use ( $page ): void {
				$page->revokeGrant();
			},
			'link you followed has expired'
		);

		$_POST    = array(
			'action'   => 'charter_oauth_revoke_all_site_grants',
			'_wpnonce' => wp_create_nonce( 'charter_oauth_revoke_all_site_grants:' . hash( 'sha256', $this->issuer ) ),
		);
		$_REQUEST = $_POST; // phpcs:ignore WordPress.Security.NonceVerification.Missing -- Test synchronizes request superglobals before the production handler verifies the nonce.
		$this->withDieHandler(
			static function () use ( $page ): void {
				$page->revokeAllGrants();
			},
			'could not be revoked'
		);
		self::assertSame( 2, $plugin->credentials()->countActiveGrantsForIssuer( $this->issuer ) );
	}

	/** Verifies affected users see retained reason and one grouped next-page notice. */
	public function testConnectedAppsShowsOnlyOwnRevocationReasonAndOneNotice(): void {
		$plugin    = Plugin::boot();
		$actorId   = self::factory()->user->create( array( 'role' => 'administrator' ) );
		$firstUser = self::factory()->user->create( array( 'role' => 'subscriber' ) );
		$otherUser = self::factory()->user->create( array( 'role' => 'subscriber' ) );
		$first     = $this->issueTokens( self::CLIENT_ONE, $firstUser );
		$other     = $this->issueTokens( self::CLIENT_TWO, $otherUser );
		self::assertInstanceOf( GrantRecord::class, $plugin->grantGovernance()->revoke( $this->issuer, $first['grant']->id(), $actorId, time() ) );

		$page = new ConnectedAppsPage( $plugin->siteState(), $plugin->clients(), $plugin->credentials() );
		wp_set_current_user( $firstUser );
		ob_start();
		$page->render();
		$html = (string) ob_get_clean();
		self::assertStringContainsString( 'id="charter-connected-apps-root"', $html );
		self::assertStringContainsString( 'id="charter-connected-apps-data"', $html );
		self::assertStringContainsString( 'Recently disconnected', $html );
		self::assertStringContainsString( 'A site administrator revoked this authorization.', $html );
		self::assertStringContainsString( self::CLIENT_ONE, $html );
		self::assertStringNotContainsString( self::CLIENT_TWO, $html );
		self::assertStringNotContainsString( $first['access_token'], $html );
		self::assertStringNotContainsString( $other['access_token'], $html );

		ob_start();
		$page->renderRevocationNotice();
		$notice = (string) ob_get_clean();
		self::assertStringContainsString( 'One OAuth authorization was revoked', $notice );
		self::assertStringContainsString( 'Review disconnected apps and reasons.', $notice );
		ob_start();
		$page->renderRevocationNotice();
		self::assertSame( '', (string) ob_get_clean() );
	}

	/**
	 * Issues one continuing grant and its first token pair.
	 *
	 * @param string $clientId Exact registered client identifier.
	 * @param int    $userId Represented WordPress user.
	 * @return array{grant:GrantRecord,access_token:string,refresh_token:string}
	 */
	private function issueTokens( string $clientId, int $userId ): array {
		$plugin   = Plugin::boot();
		$consent  = $plugin->authorization()->begin(
			array(
				'response_type'         => 'code',
				'client_id'             => $clientId,
				'redirect_uri'          => self::REDIRECT,
				'code_challenge'        => TokenService::s256Challenge( self::VERIFIER ),
				'code_challenge_method' => 'S256',
				'resource'              => $this->issuer,
				'scope'                 => AuthorizationService::GENERAL_SCOPE . ' ' . AuthorizationService::OFFLINE_ACCESS_SCOPE,
				'state'                 => 'administrator-governance-state',
			),
			$userId
		);
		$redirect = $plugin->authorization()->complete( $consent['transaction'], $userId, true );
		parse_str( (string) wp_parse_url( $redirect, PHP_URL_QUERY ), $parameters );
		self::assertIsString( $parameters['code'] ?? null );
		$tokens = $plugin->tokens()->exchange(
			array(
				'grant_type'    => Client::GRANT_AUTHORIZATION_CODE,
				'client_id'     => $clientId,
				'code'          => $parameters['code'],
				'code_verifier' => self::VERIFIER,
			)
		);
		$grants = $plugin->credentials()->listActiveGrantsForUser( $this->issuer, $userId );
		self::assertCount( 1, $grants );
		self::assertIsString( $tokens['access_token'] ?? null );
		self::assertIsString( $tokens['refresh_token'] ?? null );

		return array(
			'grant'         => $grants[0],
			'access_token'  => $tokens['access_token'],
			'refresh_token' => $tokens['refresh_token'],
		);
	}

	/** Returns the production Settings screen with its composed services. */
	private function settingsPage(): SettingsPage {
		$plugin = Plugin::boot();

		return new SettingsPage( $plugin->siteState(), $plugin->clients(), $plugin->credentials(), $plugin->clientGovernance(), $plugin->grantGovernance(), $plugin->audit(), $plugin->containment(), $plugin->signingKeys() );
	}

	/**
	 * Confirms a previously issued access token no longer validates.
	 *
	 * @param string $token Previously issued opaque access token.
	 */
	private function assertTokenRejected( string $token ): void {
		try {
			Plugin::boot()->tokens()->validateAccessToken( $token, $this->issuer, array( AuthorizationService::GENERAL_SCOPE ) );
			self::fail( 'A revoked grant access token remained valid.' );
		} catch ( ProtocolException $exception ) {
			self::assertSame( 'invalid_token', $exception->error() );
		}
	}

	/**
	 * Runs one failing WordPress action through a deterministic test die handler.
	 *
	 * @param callable $callback Protected operation expected to stop.
	 * @param string   $expectedMessage Expected non-secret error fragment.
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
			self::fail( 'The protected administrator action did not stop.' );
		} catch ( RuntimeException $exception ) {
			self::assertStringContainsString( $expectedMessage, $exception->getMessage() );
		} finally {
			remove_filter( 'wp_die_handler', $filter );
		}
	}
}
