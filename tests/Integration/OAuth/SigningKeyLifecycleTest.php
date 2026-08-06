<?php
/**
 * Production explicit signing-key lifecycle integration tests.
 *
 * @package GalatanOvidiu\Charter
 */

declare(strict_types=1);

namespace GalatanOvidiu\Charter\Tests\Integration\OAuth;

use GalatanOvidiu\Charter\Admin\SettingsPage;
use GalatanOvidiu\Charter\Http\BoundedDirectJsonFetcher;
use GalatanOvidiu\Charter\Http\MetadataController;
use GalatanOvidiu\Charter\OAuth\AuthorizationService;
use GalatanOvidiu\Charter\OAuth\Client;
use GalatanOvidiu\Charter\OAuth\ClientMetadataResolver;
use GalatanOvidiu\Charter\OAuth\CredentialHasher;
use GalatanOvidiu\Charter\OAuth\CredentialStore;
use GalatanOvidiu\Charter\OAuth\DynamicRegistrationException;
use GalatanOvidiu\Charter\OAuth\DynamicRegistrationService;
use GalatanOvidiu\Charter\OAuth\ProtocolException;
use GalatanOvidiu\Charter\OAuth\SigningKeyLifecycle;
use GalatanOvidiu\Charter\OAuth\TokenService;
use GalatanOvidiu\Charter\Plugin;
use GalatanOvidiu\Charter\Schema;
use GalatanOvidiu\Charter\Security\AuditWriter;
use GalatanOvidiu\Charter\Security\BoundedHostResolver;
use RuntimeException;
use WP_REST_Request;
use WP_UnitTestCase;

/**
 * Exercises mismatch, restoration, adoption, and no-resurrection behavior.
 *
 * @since 0.1.0
 */
final class SigningKeyLifecycleTest extends WP_UnitTestCase {

	private const CLIENT_ID    = 'charter-explicit-key-client';
	private const REDIRECT_URI = 'https://explicit-key-client.example.test/callback';
	private const VERIFIER     = '0123456789abcdefghijklmnopqrstuvwxyzABCDEFG';

	/**
	 * Current request-local explicit-key phase.
	 *
	 * @var string
	 */
	private string $keyPhase = 'a';

	/**
	 * Exact enabled issuer.
	 *
	 * @var string
	 */
	private string $issuer;

	/**
	 * Represented WordPress user.
	 *
	 * @var int
	 */
	private int $userId;

	/**
	 * Key lifecycle using the phase-controlled in-memory source.
	 *
	 * @var SigningKeyLifecycle
	 */
	private SigningKeyLifecycle $signingKeys;

	/**
	 * Credential store bound to the controlled key lifecycle.
	 *
	 * @var CredentialStore
	 */
	private CredentialStore $credentials;

	/**
	 * Authorization service bound to the controlled key lifecycle.
	 *
	 * @var AuthorizationService
	 */
	private AuthorizationService $authorization;

	/**
	 * Token service bound to the controlled key lifecycle.
	 *
	 * @var TokenService
	 */
	private TokenService $tokens;

	/**
	 * Dynamic registration service bound to the controlled key lifecycle.
	 *
	 * @var DynamicRegistrationService
	 */
	private DynamicRegistrationService $dynamicRegistration;

	/** Installs persistent production tables before per-test transactions. */
	public static function set_up_before_class(): void {
		parent::set_up_before_class();
		Schema::install();
	}

	/** Creates one enabled issuer and isolated production service composition. */
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
		$plugin->signingKeys()->delete();
		$plugin->siteState()->delete();
		self::assertTrue( $plugin->siteState()->prepareCurrentSite() );
		$identity = $plugin->siteState()->identity();
		self::assertNotNull( $identity );
		$this->issuer = $identity->issuer();
		self::assertTrue( $plugin->siteState()->recordDiscoveryVerification( $this->issuer ) );
		self::assertTrue( $plugin->siteState()->enable( $this->issuer ) );
		self::assertTrue( $plugin->clients()->registerPublicClient( $this->issuer, self::CLIENT_ID, 'Explicit key client', array( self::REDIRECT_URI ), true ) );
		$this->userId = self::factory()->user->create( array( 'role' => 'subscriber' ) );

		$this->keyPhase            = 'a';
		$this->signingKeys         = new SigningKeyLifecycle(
			$plugin->siteState(),
			$plugin->audit(),
			function (): array {
				return array(
					'source'            => SigningKeyLifecycle::SOURCE_EXPLICIT,
					'root'              => 'invalid' === $this->keyPhase ? null : $this->rootForPhase( $this->keyPhase ),
					'database_fallback' => false,
				);
			}
		);
		$this->credentials         = new CredentialStore( new CredentialHasher( $this->signingKeys ) );
		$resolver                  = new ClientMetadataResolver( $plugin->clients(), $plugin->clientMetadataSnapshots(), new BoundedHostResolver(), new BoundedDirectJsonFetcher() );
		$this->authorization       = new AuthorizationService( $plugin->siteState(), $plugin->clients(), $this->credentials, $resolver, $plugin->rateLimiter(), $plugin->audit(), $plugin->accessPolicy(), $plugin->containment(), $this->signingKeys );
		$this->tokens              = new TokenService( $plugin->siteState(), $plugin->clients(), $this->credentials, $plugin->accessPolicy(), $plugin->containment(), $this->signingKeys );
		$this->dynamicRegistration = new DynamicRegistrationService( $plugin->siteState(), $plugin->clients(), $plugin->rateLimiter(), $plugin->audit(), $plugin->containment(), $this->signingKeys );
		wp_set_current_user( 0 );
	}

	/** Removes current-site production and guard state. */
	public function tear_down(): void {
		$plugin = Plugin::boot();
		$plugin->credentials()->deleteAll();
		$plugin->clients()->deleteAll();
		$plugin->clientMetadataSnapshots()->deleteAll();
		$plugin->audit()->deleteAll();
		$plugin->rateLimiter()->deleteAll();
		$plugin->containment()->delete();
		$this->signingKeys->delete();
		$plugin->siteState()->delete();
		wp_set_current_user( 0 );
		parent::tear_down();
	}

	/**
	 * Verifies mismatch is read-only, restoration is reversible, and adoption
	 * changes only the key guard plus secret-free audit generation.
	 */
	public function testExplicitMismatchRestoreAndAdoptionPreserveStateAndPreventResurrection(): void {
		$plugin        = Plugin::boot();
		$administrator = self::factory()->user->create( array( 'role' => 'administrator' ) );
		$initial       = $this->signingKeys->snapshot();
		self::assertSame( SigningKeyLifecycle::STATUS_MATCHING, $initial['status'] );
		self::assertSame( 0, $initial['generation'] );
		self::assertSame( 0, $initial['adoption_count'] );

		$issuedA     = $this->issueTokens();
		$pending     = $this->authorization->begin( $this->authorizationParameters(), $this->userId );
		$pendingCode = $this->authorizeCode();
		$before      = $this->stateCounts();
		$stateBefore = $this->stateFingerprint();
		$auditBefore = count( $plugin->audit()->listForIssuer( $this->issuer, 100 ) );

		$this->keyPhase = 'b';
		$mismatch       = $this->signingKeys->snapshot();
		self::assertSame( SigningKeyLifecycle::STATUS_MISMATCH, $mismatch['status'] );
		self::assertIsString( $mismatch['mismatch_id'] );
		self::assertFalse( $this->signingKeys->credentialOperationsAllowed() );
		self::assertSame( 'critical', $this->signingKeys->siteHealthResult()['status'] );

		$this->assertProtocolError(
			'temporarily_unavailable',
			fn () => $this->authorization->begin( $this->authorizationParameters(), $this->userId ),
			false
		);
		$this->assertProtocolError(
			'temporarily_unavailable',
			fn () => $this->authorization->complete( $pending['transaction'], $this->userId, true ),
			false
		);
		$this->assertProtocolError(
			'temporarily_unavailable',
			fn () => $this->tokens->exchange( $this->codeExchangeParameters( $pendingCode ) )
		);
		$this->assertProtocolError(
			'invalid_token',
			fn () => $this->tokens->validateAccessToken( $issuedA['access_token'], $this->issuer, array( AuthorizationService::GENERAL_SCOPE ) )
		);
		$this->tokens->revoke(
			array(
				'client_id' => self::CLIENT_ID,
				'token'     => $issuedA['access_token'],
			)
		);
		try {
			$this->dynamicRegistration->register( $this->dynamicRegistrationBody() );
			self::fail( 'Explicit mismatch must reject DCR before registration state changes.' );
		} catch ( DynamicRegistrationException $exception ) {
			self::assertSame( 'temporarily_unavailable', $exception->error() );
			self::assertSame( 503, $exception->status() );
		}
		$metadata = ( new MetadataController( $plugin->siteState(), $plugin->accessPolicy(), $plugin->containment(), $this->signingKeys ) )->authorizationServer( new WP_REST_Request( 'GET', '/charter/v1/metadata/authorization-server' ) );
		self::assertInstanceOf( \WP_REST_Response::class, $metadata );
		self::assertArrayNotHasKey( 'registration_endpoint', $metadata->get_data() );
		self::assertSame( $before, $this->stateCounts(), 'Mismatch checks must not mutate OAuth data or rate counters.' );
		self::assertSame( $stateBefore, $this->stateFingerprint(), 'Mismatch checks must not rewrite any OAuth row or guard field.' );
		self::assertSame( $auditBefore, count( $plugin->audit()->listForIssuer( $this->issuer, 100 ) ), 'Mismatch observation must not append audit state.' );

		$this->keyPhase = 'a';
		self::assertSame( SigningKeyLifecycle::STATUS_MATCHING, $this->signingKeys->snapshot()['status'] );
		self::assertSame( $this->userId, $this->tokens->validateAccessToken( $issuedA['access_token'], $this->issuer, array( AuthorizationService::GENERAL_SCOPE ) )->userId() );
		self::assertSame( $before, $this->stateCounts(), 'Restoring the accepted key must not rewrite OAuth state.' );
		self::assertSame( $stateBefore, $this->stateFingerprint(), 'Restoring the accepted key must not rewrite any OAuth row or guard field.' );

		$this->keyPhase = 'b';
		$mismatchId     = $this->signingKeys->snapshot()['mismatch_id'];
		self::assertIsString( $mismatchId );
		self::assertTrue( $this->signingKeys->adoptReplacement( SigningKeyLifecycle::ACTOR_SITE_ADMIN, $administrator, time(), $this->issuer, $mismatchId ) );
		$adoptedB = $this->signingKeys->snapshot();
		self::assertSame( SigningKeyLifecycle::STATUS_MATCHING, $adoptedB['status'] );
		self::assertSame( 1, $adoptedB['generation'] );
		self::assertSame( 1, $adoptedB['adoption_count'] );
		self::assertFalse( $adoptedB['audit_pending'] );
		$this->assertProtocolError(
			'invalid_token',
			fn () => $this->tokens->validateAccessToken( $issuedA['access_token'], $this->issuer, array( AuthorizationService::GENERAL_SCOPE ) )
		);
		$afterAdoption = $this->stateCounts();
		self::assertSame( $before['clients'], $afterAdoption['clients'] );
		self::assertSame( $before['grants'], $afterAdoption['grants'] );
		self::assertSame( $before['credentials'], $afterAdoption['credentials'] );
		self::assertSame( $before['rates'], $afterAdoption['rates'] );
		self::assertSame( $auditBefore + 1, $afterAdoption['audit'] );

		$issuedB = $this->issueTokens();
		self::assertSame( $this->userId, $this->tokens->validateAccessToken( $issuedB['access_token'], $this->issuer, array( AuthorizationService::GENERAL_SCOPE ) )->userId() );

		$this->keyPhase = 'a';
		self::assertSame( SigningKeyLifecycle::STATUS_MISMATCH, $this->signingKeys->snapshot()['status'] );
		$this->assertProtocolError(
			'invalid_token',
			fn () => $this->tokens->validateAccessToken( $issuedA['access_token'], $this->issuer, array( AuthorizationService::GENERAL_SCOPE ) )
		);
		$mismatchA = $this->signingKeys->snapshot()['mismatch_id'];
		self::assertIsString( $mismatchA );
		self::assertTrue( $this->signingKeys->adoptReplacement( SigningKeyLifecycle::ACTOR_SITE_ADMIN, $administrator, time(), $this->issuer, $mismatchA ) );
		self::assertSame( 2, $this->signingKeys->snapshot()['generation'] );
		$this->assertProtocolError(
			'invalid_token',
			fn () => $this->tokens->validateAccessToken( $issuedA['access_token'], $this->issuer, array( AuthorizationService::GENERAL_SCOPE ) )
		);

		$events = array_values( array_filter( $plugin->audit()->listForIssuer( $this->issuer, 100 ), static fn ( $event ): bool => 'root_key_replacement_adopted' === $event->eventType() ) );
		self::assertCount( 2, $events );
		self::assertSame( 'site_administrator_explicit_key_replacement', $events[0]->reason() );
		$auditJson = wp_json_encode( $events );
		self::assertIsString( $auditJson );
		self::assertStringNotContainsString( $this->rootForPhase( 'a' ), $auditJson );
		self::assertStringNotContainsString( $this->rootForPhase( 'b' ), $auditJson );
	}

	/** Verifies malformed persisted guard state cannot auto-adopt configuration. */
	public function testMalformedExplicitGuardFailsClosedWithoutReplacement(): void {
		self::assertSame( SigningKeyLifecycle::STATUS_MATCHING, $this->signingKeys->snapshot()['status'] );
		update_option( 'charter_oauth_signing_key_guard', array( 'malformed' => true ), false );

		$snapshot = $this->signingKeys->snapshot();
		self::assertSame( SigningKeyLifecycle::STATUS_UNESTABLISHED, $snapshot['status'] );
		self::assertFalse( $this->signingKeys->credentialOperationsAllowed() );
		self::assertSame( array( 'malformed' => true ), get_option( 'charter_oauth_signing_key_guard' ) );
	}

	/** Verifies invalid explicit configuration cannot turn RFC 7009 into an error oracle. */
	public function testInvalidExplicitRootFailsClosedWhileRevocationRemainsANonRevealingNoOp(): void {
		$issued = $this->issueTokens();
		$before = $this->stateCounts();

		$this->keyPhase = 'invalid';
		self::assertSame( SigningKeyLifecycle::STATUS_INVALID, $this->signingKeys->snapshot()['status'] );
		self::assertFalse( $this->signingKeys->credentialOperationsAllowed() );
		$this->tokens->revoke(
			array(
				'client_id' => self::CLIENT_ID,
				'token'     => $issued['access_token'],
			)
		);
		$this->assertProtocolError(
			'invalid_token',
			fn () => $this->tokens->validateAccessToken( $issued['access_token'], $this->issuer, array( AuthorizationService::GENERAL_SCOPE ) )
		);
		$this->assertProtocolError(
			'temporarily_unavailable',
			fn () => $this->authorization->begin( $this->authorizationParameters(), $this->userId ),
			false
		);
		self::assertSame( $before, $this->stateCounts() );
	}

	/** Verifies the Site Admin surface is capability, nonce, and confirmation bound. */
	public function testSiteAdministratorControlsExposeTruthfulBoundStateWithoutSecrets(): void {
		$plugin = Plugin::boot();
		self::assertSame( SigningKeyLifecycle::STATUS_MATCHING, $this->signingKeys->snapshot()['status'] );
		$this->keyPhase = 'b';
		$mismatch       = $this->signingKeys->snapshot();
		$mismatchId     = $mismatch['mismatch_id'];
		self::assertIsString( $mismatchId );

		$administrator = self::factory()->user->create( array( 'role' => 'administrator' ) );
		$page          = new SettingsPage( $plugin->siteState(), $plugin->clients(), $this->credentials, $plugin->clientGovernance(), $plugin->grantGovernance(), $plugin->audit(), $plugin->containment(), $this->signingKeys );
		wp_set_current_user( $administrator );
		ob_start();
		$page->render();
		$html        = (string) ob_get_clean();
		$nonceAction = 'charter_oauth_adopt_signing_key:' . hash( 'sha256', $this->issuer . "\0" . $mismatchId );
		self::assertStringContainsString( 'Source: explicit. Status: mismatch.', $html );
		self::assertStringContainsString( wp_create_nonce( $nonceAction ), $html );
		self::assertStringContainsString( 'name="confirm_action"', $html );
		self::assertStringContainsString( 'does not back up, export, escrow, recover, overlap, or migrate', $html );
		self::assertStringNotContainsString( $this->rootForPhase( 'a' ), $html );
		self::assertStringNotContainsString( $this->rootForPhase( 'b' ), $html );

		ob_start();
		$this->signingKeys->renderAdministratorNotice();
		$notice = (string) ob_get_clean();
		self::assertStringContainsString( 'blocking credential issuance and Charter credential validation', $notice );

		$subscriber = self::factory()->user->create( array( 'role' => 'subscriber' ) );
		wp_set_current_user( $subscriber );
		ob_start();
		$this->signingKeys->renderAdministratorNotice();
		self::assertSame( '', (string) ob_get_clean() );
		$this->withDieHandler( static fn () => $page->render(), 'not allowed to manage Charter OAuth' );

		wp_set_current_user( $administrator );
		$_POST    = array(
			'mismatch_id'    => $mismatchId,
			'confirm_action' => '1',
			'_wpnonce'       => 'invalid-nonce',
		);
		$_REQUEST = $_POST; // phpcs:ignore WordPress.Security.NonceVerification.Missing -- The production handler verifies the synchronized request.
		$this->withDieHandler( static fn () => $page->adoptSigningKey(), 'link you followed has expired' );

		$_POST    = array(
			'mismatch_id' => $mismatchId,
			'_wpnonce'    => wp_create_nonce( $nonceAction ),
		);
		$_REQUEST = $_POST; // phpcs:ignore WordPress.Security.NonceVerification.Missing -- The production handler verifies the synchronized request.
		$this->withDieHandler( static fn () => $page->adoptSigningKey(), 'key replacement could not be adopted' );

		$this->keyPhase = 'c';
		$_POST          = array(
			'mismatch_id'    => $mismatchId,
			'confirm_action' => '1',
			'_wpnonce'       => wp_create_nonce( $nonceAction ),
		);
		$_REQUEST       = $_POST; // phpcs:ignore WordPress.Security.NonceVerification.Missing -- The production handler verifies the synchronized request.
		$this->withDieHandler( static fn () => $page->adoptSigningKey(), 'key replacement could not be adopted' );
		self::assertSame( 0, $this->signingKeys->snapshot()['generation'] );
	}

	/** Verifies an applied replacement retains one exact recoverable audit transition. */
	public function testInterruptedAdoptionAuditBlocksAnotherAdoptionUntilExactReconciliation(): void {
		self::assertSame( SigningKeyLifecycle::STATUS_MATCHING, $this->signingKeys->snapshot()['status'] );
		$audit          = new class() implements AuditWriter {
			/**
			 * Whether writes should fail.
			 *
			 * @var bool
			 */
			public bool $fail = true;

			/**
			 * Recorded exact events.
			 *
			 * @var array<int, array{issuer:string,event_type:string,outcome:string,reason:string,actor_user_id:?int,timestamp:int}>
			 */
			public array $events = array();

			/**
			 * Records one exact event unless failure is enabled.
			 *
			 * @param string      $issuer Exact issuer.
			 * @param string      $eventType Stable event type.
			 * @param string      $outcome Stable outcome.
			 * @param string      $reason Stable reason.
			 * @param int|null    $actorUserId Acting WordPress user.
			 * @param int|null    $representedUserId Represented user.
			 * @param string|null $clientId Exact client identifier.
			 * @param string|null $sourceAddress Normalized source when relevant.
			 * @param int|null    $timestamp Event timestamp.
			 * @param string|null $resourceIdentifier Exact resource when applicable.
			 * @param string|null $scopes Canonical scopes when applicable.
			 * @throws RuntimeException While failure is enabled.
			 */
			public function record( string $issuer, string $eventType, string $outcome, string $reason, ?int $actorUserId = null, ?int $representedUserId = null, ?string $clientId = null, ?string $sourceAddress = null, ?int $timestamp = null, ?string $resourceIdentifier = null, ?string $scopes = null ): void {
				unset( $representedUserId, $clientId, $sourceAddress, $resourceIdentifier, $scopes );
				if ( $this->fail || null === $timestamp ) {
					throw new RuntimeException( 'charter_test_key_audit_interrupted' );
				}
				$this->events[] = array(
					'issuer'        => $issuer,
					'event_type'    => $eventType,
					'outcome'       => $outcome,
					'reason'        => $reason,
					'actor_user_id' => $actorUserId,
					'timestamp'     => $timestamp,
				);
			}

			/**
			 * Reports whether one exact event was already recorded.
			 *
			 * @param string   $issuer Exact issuer.
			 * @param int      $timestamp Exact event timestamp.
			 * @param string   $eventType Stable event type.
			 * @param string   $outcome Stable outcome.
			 * @param string   $reason Stable reason.
			 * @param int|null $actorUserId Acting WordPress user.
			 */
			public function hasEvent( string $issuer, int $timestamp, string $eventType, string $outcome, string $reason, ?int $actorUserId ): bool {
				foreach ( $this->events as $event ) {
					if ( array( $issuer, $timestamp, $eventType, $outcome, $reason, $actorUserId ) === array( $event['issuer'], $event['timestamp'], $event['event_type'], $event['outcome'], $event['reason'], $event['actor_user_id'] ) ) {
						return true;
					}
				}

				return false;
			}
		};
		$lifecycle      = new SigningKeyLifecycle(
			Plugin::boot()->siteState(),
			$audit,
			function (): array {
				return array(
					'source'            => SigningKeyLifecycle::SOURCE_EXPLICIT,
					'root'              => 'invalid' === $this->keyPhase ? null : $this->rootForPhase( $this->keyPhase ),
					'database_fallback' => false,
				);
			}
		);
		$actorId        = self::factory()->user->create( array( 'role' => 'administrator' ) );
		$timestamp      = time();
		$this->keyPhase = 'b';
		$mismatchId     = $lifecycle->snapshot()['mismatch_id'];
		self::assertIsString( $mismatchId );
		self::assertTrue( $lifecycle->adoptReplacement( SigningKeyLifecycle::ACTOR_SITE_ADMIN, $actorId, $timestamp, $this->issuer, $mismatchId ) );
		$pending = $lifecycle->snapshot();
		self::assertTrue( $pending['audit_pending'] );
		self::assertSame( 1, $pending['generation'] );
		self::assertSame( 'critical', $lifecycle->siteHealthResult()['status'] );
		self::assertSame( array(), $audit->events );
		$transitionId = $pending['transition_id'];
		$appliedAt    = $pending['changed_at'];
		self::assertIsString( $transitionId );
		self::assertIsInt( $appliedAt );

		$this->keyPhase = 'c';
		$nextMismatch   = $lifecycle->snapshot()['mismatch_id'];
		self::assertIsString( $nextMismatch );
		self::assertFalse( $lifecycle->adoptReplacement( SigningKeyLifecycle::ACTOR_SITE_ADMIN, $actorId, $timestamp + 1, $this->issuer, $nextMismatch ) );
		self::assertSame( 1, $lifecycle->snapshot()['generation'] );

		$audit->fail = false;
		self::assertTrue( $lifecycle->reconcilePendingAudit( $this->issuer, $transitionId ) );
		self::assertFalse( $lifecycle->snapshot()['audit_pending'] );
		self::assertCount( 1, $audit->events );
		self::assertSame( $appliedAt, $audit->events[0]['timestamp'] );
		self::assertSame( 'site_administrator_explicit_key_replacement', $audit->events[0]['reason'] );
		self::assertFalse( $lifecycle->reconcilePendingAudit( $this->issuer, $transitionId ) );
		self::assertTrue( $lifecycle->adoptReplacement( SigningKeyLifecycle::ACTOR_SITE_ADMIN, $actorId, $timestamp + 1, $this->issuer, $nextMismatch ) );
		self::assertCount( 2, $audit->events );
		$projection = wp_json_encode( $audit->events );
		self::assertIsString( $projection );
		self::assertStringNotContainsString( $this->rootForPhase( 'a' ), $projection );
		self::assertStringNotContainsString( $this->rootForPhase( 'b' ), $projection );
		self::assertStringNotContainsString( $this->rootForPhase( 'c' ), $projection );
	}

	/** Issues one complete authorization-code and refresh-capable credential set. */
	private function issueTokens(): array {
		$code = $this->authorizeCode();

		return $this->tokens->exchange( $this->codeExchangeParameters( $code ) );
	}

	/** Creates and approves one exact authorization transaction. */
	private function authorizeCode(): string {
		$consent  = $this->authorization->begin( $this->authorizationParameters(), $this->userId );
		$redirect = $this->authorization->complete( $consent['transaction'], $this->userId, true );
		$query    = (string) wp_parse_url( $redirect, PHP_URL_QUERY );
		parse_str( $query, $parameters );
		$code = $parameters['code'] ?? null;
		self::assertIsString( $code );

		return $code;
	}

	/** Returns one exact authorization request. */
	private function authorizationParameters(): array {
		return array(
			'response_type'         => 'code',
			'client_id'             => self::CLIENT_ID,
			'redirect_uri'          => self::REDIRECT_URI,
			'code_challenge'        => TokenService::s256Challenge( self::VERIFIER ),
			'code_challenge_method' => 'S256',
			'resource'              => $this->issuer,
			'scope'                 => AuthorizationService::GENERAL_SCOPE . ' ' . AuthorizationService::OFFLINE_ACCESS_SCOPE,
			'state'                 => 'explicit-key-state',
		);
	}

	/**
	 * Returns one exact authorization-code exchange request.
	 *
	 * @param string $code Issued authorization code.
	 */
	private function codeExchangeParameters( string $code ): array {
		return array(
			'grant_type'    => Client::GRANT_AUTHORIZATION_CODE,
			'client_id'     => self::CLIENT_ID,
			'code'          => $code,
			'code_verifier' => self::VERIFIER,
			'redirect_uri'  => self::REDIRECT_URI,
			'resource'      => $this->issuer,
		);
	}

	/** Returns one valid bounded DCR request body. */
	private function dynamicRegistrationBody(): string {
		$body = wp_json_encode(
			array(
				'client_name'                => 'Mismatch registration',
				'redirect_uris'              => array( 'https://mismatch-registration.example.test/callback' ),
				'token_endpoint_auth_method' => 'none',
				'grant_types'                => array( Client::GRANT_AUTHORIZATION_CODE ),
				'response_types'             => array( 'code' ),
			)
		);
		self::assertIsString( $body );

		return $body;
	}

	/** Returns counts for every state category that mismatch must preserve. */
	private function stateCounts(): array {
		global $wpdb;

		self::assertInstanceOf( \wpdb::class, $wpdb );

		return array(
			'clients'     => count( Plugin::boot()->clients()->listForIssuer( $this->issuer ) ),
			'grants'      => $this->credentials->countActiveGrantsForIssuer( $this->issuer ),
			'credentials' => (int) $wpdb->get_var( 'SELECT COUNT(*) FROM ' . Schema::credentialTable() ), // phpcs:ignore WordPress.DB.PreparedSQL.NotPrepared -- Fixed test-owned table name without user input.
			'rates'       => (int) $wpdb->get_var( 'SELECT COUNT(*) FROM ' . Schema::rateLimitTable() ), // phpcs:ignore WordPress.DB.PreparedSQL.NotPrepared -- Fixed test-owned table name without user input.
			'audit'       => count( Plugin::boot()->audit()->listForIssuer( $this->issuer, 100 ) ),
		);
	}

	/** Returns a non-reversible digest over every exact OAuth row and guard field. */
	private function stateFingerprint(): string {
		global $wpdb;

		self::assertInstanceOf( \wpdb::class, $wpdb );
		$state = array();
		foreach ( array( Schema::clientTable(), Schema::clientMetadataTable(), Schema::grantTable(), Schema::credentialTable(), Schema::rateLimitTable(), Schema::auditTable() ) as $table ) {
			$rows = $wpdb->get_results( 'SELECT * FROM ' . $table . ' ORDER BY 1', ARRAY_A ); // phpcs:ignore WordPress.DB.PreparedSQL.NotPrepared,WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching -- Fixed test-owned table names verify exact no-write behavior.
			self::assertIsArray( $rows );
			$state[ $table ] = $rows;
		}
		$state['guard'] = get_option( 'charter_oauth_signing_key_guard' );

		return hash( 'sha256', serialize( $state ) ); // phpcs:ignore WordPress.PHP.DiscouragedPHPFunctions.serialize_serialize -- Test-only opaque state digest is never persisted or rendered.
	}

	/**
	 * Asserts one exact protocol error without rendering sensitive inputs.
	 *
	 * @param string   $expectedError Expected OAuth error code.
	 * @param callable $operation     Protocol operation under test.
	 * @param bool     $expectStatus  Whether to assert a bounded HTTP status.
	 */
	private function assertProtocolError( string $expectedError, callable $operation, bool $expectStatus = true ): void {
		try {
			$operation();
			self::fail( 'The signing-key gate did not reject the protocol operation.' );
		} catch ( ProtocolException $exception ) {
			self::assertSame( $expectedError, $exception->error() );
			if ( $expectStatus ) {
				self::assertContains( $exception->status(), array( 400, 401, 503 ) );
			}
			self::assertNull( $exception->redirectUri(), 'An unresolved key mismatch must not gain or reuse client redirect authority.' );
		}
	}

	/**
	 * Returns deterministic request-local test root material without output.
	 *
	 * @param string $phase Test-only key phase.
	 */
	private function rootForPhase( string $phase ): string {
		return hash( 'sha256', 'charter-production-explicit-key-phase:' . $phase );
	}

	/**
	 * Runs one failing WordPress action through a deterministic die handler.
	 *
	 * @param callable $callback Protected operation expected to stop.
	 * @param string   $expectedMessage Expected non-secret error fragment.
	 */
	private function withDieHandler( callable $callback, string $expectedMessage ): void {
		$filter = static function (): callable {
			return static function ( mixed $message ): never {
				$text = is_string( $message ) ? wp_strip_all_tags( $message ) : '';
				throw new RuntimeException( $text ); // phpcs:ignore WordPress.Security.EscapeOutput.ExceptionNotEscaped -- Test-only control flow; never rendered.
			};
		};
		add_filter( 'wp_die_handler', $filter );
		try {
			$callback();
			self::fail( 'The protected signing-key action did not stop.' );
		} catch ( RuntimeException $exception ) {
			self::assertStringContainsString( $expectedMessage, $exception->getMessage() );
		} finally {
			remove_filter( 'wp_die_handler', $filter );
		}
	}
}
