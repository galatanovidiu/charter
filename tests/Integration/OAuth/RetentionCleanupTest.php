<?php
/**
 * OAuth retention, scheduling, and diagnostics integration tests.
 *
 * @package GalatanOvidiu\Charter
 */

declare(strict_types=1);

namespace GalatanOvidiu\Charter\Tests\Integration\OAuth;

use GalatanOvidiu\Charter\OAuth\AuthorizationRequest;
use GalatanOvidiu\Charter\OAuth\AuthorizationService;
use GalatanOvidiu\Charter\OAuth\Client;
use GalatanOvidiu\Charter\OAuth\ClientCleanup;
use GalatanOvidiu\Charter\OAuth\CredentialStore;
use GalatanOvidiu\Charter\OAuth\ProtocolException;
use GalatanOvidiu\Charter\OAuth\TokenService;
use GalatanOvidiu\Charter\OAuth\TransactionManager;
use GalatanOvidiu\Charter\Plugin;
use GalatanOvidiu\Charter\Schema;
use mysqli;
use RuntimeException;
use WP_Error;
use WP_UnitTestCase;

/**
 * Proves D30-D31 retention and request-time validity independence.
 *
 * @since 0.1.0
 */
final class RetentionCleanupTest extends WP_UnitTestCase {

	private const CLIENT_ID = 'retention-test-client';
	private const REDIRECT  = 'https://retention-client.example.test/callback';
	private const VERIFIER  = '0123456789abcdefghijklmnopqrstuvwxyzABCDEFG';

	/**
	 * Exact prepared issuer.
	 *
	 * @var string
	 */
	private string $issuer;

	/** Installs persistent tables before Core test transactions. */
	public static function set_up_before_class(): void {
		parent::set_up_before_class();
		Schema::install();
	}

	/** Creates one clean enabled site issuer. */
	public function set_up(): void {
		parent::set_up();
		$plugin = Plugin::boot();
		Schema::install();
		$plugin->credentials()->deleteAll();
		$plugin->clients()->deleteAll();
		$plugin->clientMetadataSnapshots()->deleteAll();
		$plugin->audit()->deleteAll();
		$plugin->rateLimiter()->deleteAll();
		$plugin->cleanup()->deleteStatus();
		$plugin->siteState()->delete();
		wp_unschedule_hook( ClientCleanup::HOOK );
		self::assertTrue( $plugin->siteState()->prepareCurrentSite() );
		$identity = $plugin->siteState()->identity();
		self::assertNotNull( $identity );
		$this->issuer = $identity->issuer();
		self::assertTrue( $plugin->siteState()->recordDiscoveryVerification( $this->issuer ) );
		self::assertTrue( $plugin->siteState()->enable( $this->issuer ) );
	}

	/** Removes current-site fixtures and cron state. */
	public function tear_down(): void {
		remove_filter( 'pre_schedule_event', array( $this, 'rejectSchedule' ), 10 );
		wp_unschedule_hook( ClientCleanup::HOOK );
		$plugin = Plugin::boot();
		$plugin->credentials()->deleteAll();
		$plugin->clients()->deleteAll();
		$plugin->audit()->deleteAll();
		$plugin->cleanup()->deleteStatus();
		$plugin->siteState()->delete();
		wp_set_current_user( 0 );
		parent::tear_down();
	}

	/** Verifies every accepted retention window and idempotent physical deletion. */
	public function testCleanupDeletesOnlyEligibleIssuerRecords(): void {
		$timestamp = time();
		$this->insertRetentionFixtures( $timestamp );

		$result = Plugin::boot()->cleanup()->execute( $timestamp );
		self::assertSame(
			array(
				'transactions'    => 1,
				'codes'           => 2,
				'access_tokens'   => 1,
				'refresh_tokens'  => 2,
				'dynamic_clients' => 2,
				'grants'          => 1,
				'audit_events'    => 1,
			),
			$result->deleted()
		);
		self::assertFalse( $result->hasMore() );
		self::assertSame( 0, $this->countCredential( 'fixture_transaction_old' ) );
		self::assertSame( 1, $this->countCredential( 'fixture_transaction_recent' ) );
		self::assertSame( 0, $this->countCredential( 'fixture_code_consumed_old' ) );
		self::assertSame( 0, $this->countCredential( 'fixture_code_expired_old' ) );
		self::assertSame( 1, $this->countCredential( 'fixture_code_recent' ) );
		self::assertSame( 0, $this->countCredential( 'fixture_access_old' ) );
		self::assertSame( 1, $this->countCredential( 'fixture_access_recent' ) );
		self::assertSame( 0, $this->countCredential( 'fixture_refresh_revoked_old' ) );
		self::assertSame( 1, $this->countCredential( 'fixture_refresh_revoked_recent' ) );
		self::assertSame( 0, $this->countCredential( 'fixture_refresh_expired_old' ) );
		self::assertSame( 0, $this->countClient( 'dynamic-unused-old' ) );
		self::assertSame( 1, $this->countClient( 'dynamic-unused-recent' ) );
		self::assertSame( 0, $this->countClient( 'dynamic-inactive-old' ) );
		self::assertSame( 1, $this->countClient( 'dynamic-active-grant' ) );
		self::assertSame( 0, $this->countGrantReason( 'fixture_terminal_old' ) );
		self::assertSame( 1, $this->countGrantReason( 'fixture_terminal_recent' ) );
		self::assertSame( 0, $this->countAuditReason( 'fixture_old' ) );
		self::assertSame( 1, $this->countAuditReason( 'fixture_recent' ) );

		$idempotent = Plugin::boot()->cleanup()->execute( $timestamp + 1 );
		self::assertSame( 0, $idempotent->totalDeleted() );
		self::assertSame( 'current', Plugin::boot()->cleanup()->statusSnapshot( $timestamp + 1 )['state'] );
		self::assertSame( 'good', Plugin::boot()->cleanup()->siteHealthResult()['status'] );
	}

	/** Verifies finite continuations, overdue state, and stable failure diagnostics. */
	public function testCronSchedulingContinuationAndSiteHealthAreObservable(): void {
		$timestamp = time();
		$this->insertOldTransactions( $timestamp, 3 );

		Plugin::boot()->cleanup()->schedule();
		self::assertNotFalse( wp_next_scheduled( ClientCleanup::HOOK, array( 'daily' ) ) );
		$first = Plugin::boot()->cleanup()->execute( $timestamp, 2, true );
		self::assertSame( 2, $first->totalDeleted() );
		self::assertTrue( $first->hasMore() );
		self::assertNotFalse( wp_next_scheduled( ClientCleanup::HOOK, array( 'continuation' ) ) );
		$second = Plugin::boot()->cleanup()->execute( $timestamp + 1, 2, true );
		self::assertSame( 1, $second->totalDeleted() );
		self::assertFalse( $second->hasMore() );
		self::assertSame( $timestamp + 1, Plugin::boot()->cleanup()->statusSnapshot( $timestamp + 1 )['last_completed_at'] );

		Plugin::boot()->cleanup()->deleteStatus();
		Plugin::boot()->cleanup()->execute( $timestamp - 3 * DAY_IN_SECONDS );
		self::assertSame( 'overdue', Plugin::boot()->cleanup()->statusSnapshot( $timestamp )['state'] );

		Plugin::boot()->cleanup()->deleteStatus();
		wp_unschedule_hook( ClientCleanup::HOOK );
		add_filter( 'pre_schedule_event', array( $this, 'rejectSchedule' ), 10, 3 );
		Plugin::boot()->cleanup()->schedule();
		self::assertSame( 'failed', Plugin::boot()->cleanup()->statusSnapshot( $timestamp )['state'] );
		self::assertSame( 'critical', Plugin::boot()->cleanup()->siteHealthResult()['status'] );
		self::assertSame( 1, $this->countAuditReason( 'cleanup_scheduling' ) );
		$tests = apply_filters( 'site_status_tests', array() ); // phpcs:ignore WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedHooknameFound -- Exercises the Core Site Health registry.
		self::assertIsArray( $tests['direct']['charter_oauth_cleanup'] ?? null );
	}

	/** Proves retained expired credentials fail before any cleanup is run. */
	public function testDelayedCleanupNeverDeterminesCredentialValidity(): void {
		$plugin = Plugin::boot();
		self::assertTrue( $plugin->clients()->registerPublicClient( $this->issuer, self::CLIENT_ID, 'Retention test client', array( self::REDIRECT ), true ) );
		$client = $plugin->clients()->findActive( $this->issuer, self::CLIENT_ID );
		self::assertNotNull( $client );
		$userId = self::factory()->user->create( array( 'role' => 'subscriber' ) );

		$expiredAccess = $this->issueTokensAt( $client, $userId, time() - 2 * DAY_IN_SECONDS, false );
		self::assertNotNull( $plugin->credentials()->find( CredentialStore::ACCESS_TOKEN, $this->issuer, $expiredAccess['access_token'] ) );
		try {
			$plugin->tokens()->validateAccessToken( $expiredAccess['access_token'], $this->issuer, array( AuthorizationService::GENERAL_SCOPE ) );
			self::fail( 'A retained but expired access-token digest must not authorize.' );
		} catch ( ProtocolException $exception ) {
			self::assertSame( 'invalid_token', $exception->error() );
		}

		$expiredRefresh = $this->issueTokensAt( $client, $userId, time() - 91 * DAY_IN_SECONDS, true );
		self::assertIsString( $expiredRefresh['refresh_token'] ?? null );
		try {
			$plugin->tokens()->exchange(
				array(
					'grant_type'    => Client::GRANT_REFRESH_TOKEN,
					'client_id'     => self::CLIENT_ID,
					'refresh_token' => $expiredRefresh['refresh_token'],
				)
			);
			self::fail( 'A retained refresh member beyond inactivity expiry must not rotate.' );
		} catch ( ProtocolException $exception ) {
			self::assertSame( 'invalid_grant', $exception->error() );
		}
		self::assertNotNull( $plugin->credentials()->find( CredentialStore::REFRESH_TOKEN, $this->issuer, $expiredRefresh['refresh_token'] ) );
		self::assertNull( Plugin::boot()->cleanup()->statusSnapshot()['last_run_at'] );
	}

	/** Returns a deterministic scheduling failure. */
	public function rejectSchedule(): WP_Error {
		return new WP_Error( 'fixture_schedule_failure' );
	}

	/**
	 * Issues one complete credential family at an historical timestamp.
	 *
	 * @param Client $client Active exact client.
	 * @param int    $userId Represented user.
	 * @param int    $timestamp Historical authorization time.
	 * @param bool   $continuingAccess Whether refresh access is approved.
	 * @return array{access_token:string,refresh_token?:string}
	 */
	private function issueTokensAt( Client $client, int $userId, int $timestamp, bool $continuingAccess ): array {
		$request          = new AuthorizationRequest(
			$this->issuer,
			$this->issuer,
			$client,
			self::REDIRECT,
			AuthorizationService::GENERAL_SCOPE,
			TokenService::s256Challenge( self::VERIFIER ),
			null,
			$continuingAccess
		);
		$transactionValue = Plugin::boot()->credentials()->issueAuthorizationRequest( $request, $userId, $timestamp );
		$transaction      = Plugin::boot()->credentials()->find( CredentialStore::AUTHORIZATION_REQUEST, $this->issuer, $transactionValue );
		self::assertNotNull( $transaction );
		$codeValue = Plugin::boot()->credentials()->approveAuthorization( $transaction, $timestamp + 60 );
		self::assertIsString( $codeValue );
		$code = Plugin::boot()->credentials()->find( CredentialStore::AUTHORIZATION_CODE, $this->issuer, $codeValue );
		self::assertNotNull( $code );
		$tokens = Plugin::boot()->credentials()->exchangeAuthorizationCode( $code, $timestamp + 120 );
		self::assertIsArray( $tokens );

		return $tokens;
	}

	/**
	 * Inserts one eligible transaction per requested record.
	 *
	 * @param int $timestamp Current Unix timestamp.
	 * @param int $count Fixture count.
	 */
	private function insertOldTransactions( int $timestamp, int $count ): void {
		( new TransactionManager() )->run(
			function ( mysqli $database ) use ( $timestamp, $count ): void {
				for ( $index = 1; $index <= $count; ++$index ) {
					$this->insertCredential( $database, 'continuation_' . $index, CredentialStore::AUTHORIZATION_REQUEST, $timestamp - 2 * DAY_IN_SECONDS, null, null );
				}
			}
		);
	}

	/**
	 * Inserts exact old and recent fixtures for every D30 category.
	 *
	 * @param int $timestamp Current Unix timestamp.
	 */
	private function insertRetentionFixtures( int $timestamp ): void {
		( new TransactionManager() )->run(
			function ( mysqli $database ) use ( $timestamp ): void {
				$this->insertCredential( $database, 'fixture_transaction_old', CredentialStore::AUTHORIZATION_REQUEST, $timestamp - 2 * DAY_IN_SECONDS, null, null );
				$this->insertCredential( $database, 'fixture_transaction_recent', CredentialStore::AUTHORIZATION_REQUEST, $timestamp - 2 * HOUR_IN_SECONDS, null, null );
				$this->insertCredential( $database, 'fixture_code_consumed_old', CredentialStore::AUTHORIZATION_CODE, $timestamp - 2 * DAY_IN_SECONDS, $timestamp - 2 * DAY_IN_SECONDS, null );
				$this->insertCredential( $database, 'fixture_code_expired_old', CredentialStore::AUTHORIZATION_CODE, $timestamp - 2 * DAY_IN_SECONDS, null, null );
				$this->insertCredential( $database, 'fixture_code_recent', CredentialStore::AUTHORIZATION_CODE, $timestamp - 2 * HOUR_IN_SECONDS, $timestamp - HOUR_IN_SECONDS, null );
				$this->insertCredential( $database, 'fixture_access_old', CredentialStore::ACCESS_TOKEN, $timestamp - 2 * DAY_IN_SECONDS, null, null );
				$this->insertCredential( $database, 'fixture_access_recent', CredentialStore::ACCESS_TOKEN, $timestamp - 2 * HOUR_IN_SECONDS, null, null );

				$revokedOld = $this->insertGrant( $database, 'refresh-revoked-old', 'revoked', true, $timestamp - 31 * DAY_IN_SECONDS, $timestamp - 40 * DAY_IN_SECONDS, 'fixture_refresh_old' );
				$revokedNew = $this->insertGrant( $database, 'refresh-revoked-recent', 'revoked', true, $timestamp - 29 * DAY_IN_SECONDS, $timestamp - 40 * DAY_IN_SECONDS, 'fixture_refresh_recent' );
				$expiredOld = $this->insertGrant( $database, 'refresh-expired-old', 'active', true, null, $timestamp - 31 * DAY_IN_SECONDS, null );
				$this->insertCredential( $database, 'fixture_refresh_revoked_old', CredentialStore::REFRESH_TOKEN, $timestamp - 40 * DAY_IN_SECONDS, $timestamp - 31 * DAY_IN_SECONDS, $revokedOld );
				$this->insertCredential( $database, 'fixture_refresh_revoked_recent', CredentialStore::REFRESH_TOKEN, $timestamp - 40 * DAY_IN_SECONDS, $timestamp - 29 * DAY_IN_SECONDS, $revokedNew );
				$this->insertCredential( $database, 'fixture_refresh_expired_old', CredentialStore::REFRESH_TOKEN, $timestamp - 40 * DAY_IN_SECONDS, null, $expiredOld );

				$this->insertClient( $database, 'dynamic-unused-old', $timestamp - 8 * DAY_IN_SECONDS, $timestamp - 8 * DAY_IN_SECONDS, null );
				$this->insertClient( $database, 'dynamic-unused-recent', $timestamp - 6 * DAY_IN_SECONDS, $timestamp - 6 * DAY_IN_SECONDS, null );
				$this->insertClient( $database, 'dynamic-inactive-old', $timestamp - 100 * DAY_IN_SECONDS, $timestamp - 91 * DAY_IN_SECONDS, $timestamp - 99 * DAY_IN_SECONDS );
				$this->insertClient( $database, 'dynamic-active-grant', $timestamp - 100 * DAY_IN_SECONDS, $timestamp - 91 * DAY_IN_SECONDS, $timestamp - 99 * DAY_IN_SECONDS );
				$this->insertGrant( $database, 'dynamic-active-grant', 'active', false, null, null, null );

				$this->insertGrant( $database, 'terminal-old', 'revoked', false, $timestamp - 91 * DAY_IN_SECONDS, null, 'fixture_terminal_old' );
				$this->insertGrant( $database, 'terminal-recent', 'revoked', false, $timestamp - 89 * DAY_IN_SECONDS, null, 'fixture_terminal_recent' );
				$this->insertAudit( $database, 'fixture_old', $timestamp - 91 * DAY_IN_SECONDS );
				$this->insertAudit( $database, 'fixture_recent', $timestamp - 89 * DAY_IN_SECONDS );
			}
		);
	}

	/**
	 * Inserts one credential fixture.
	 *
	 * @param mysqli   $database Owned connection.
	 * @param string   $marker Unique fixture marker.
	 * @param string   $type Credential type.
	 * @param int      $terminalAt Expiry or creation timestamp.
	 * @param int|null $consumedAt Optional consumption timestamp.
	 * @param int|null $grantId Optional owning grant.
	 * @throws RuntimeException When fixture insertion fails.
	 */
	private function insertCredential( mysqli $database, string $marker, string $type, int $terminalAt, ?int $consumedAt, ?int $grantId ): void {
		$table  = self::quotedTable( Schema::credentialTable() );
		$result = $database->execute_query(
			"INSERT INTO {$table}
			(credential_type,digest,issuer,resource,client_id,redirect_uri,user_id,scope,code_challenge,request_state,expires_at,consumed_at,created_at,grant_id,parent_id,continuing_access,client_metadata_fingerprint)
			VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
			array( $type, hash( 'sha256', $marker ), $this->issuer, $this->issuer, $marker, self::REDIRECT, 1, AuthorizationService::GENERAL_SCOPE, '', null, $terminalAt, $consumedAt, $terminalAt, $grantId, null, CredentialStore::REFRESH_TOKEN === $type ? 1 : 0, '' )
		); // phpcs:ignore WordPress.DB.RestrictedFunctions.mysql_mysqli -- Test fixtures use the production-owned transaction boundary.
		if ( true !== $result ) {
			throw new RuntimeException( 'charter_cleanup_fixture_credential_failed' );
		}
	}

	/**
	 * Inserts one grant fixture and returns its site-local identifier.
	 *
	 * @param mysqli      $database Owned connection.
	 * @param string      $clientId Exact fixture client.
	 * @param string      $status Grant status.
	 * @param bool        $continuingAccess Whether refresh access exists.
	 * @param int|null    $revokedAt Optional terminal timestamp.
	 * @param int|null    $refreshExpiresAt Optional refresh expiry.
	 * @param string|null $reason Optional terminal reason.
	 * @throws RuntimeException When fixture insertion fails.
	 */
	private function insertGrant( mysqli $database, string $clientId, string $status, bool $continuingAccess, ?int $revokedAt, ?int $refreshExpiresAt, ?string $reason ): int {
		$table      = self::quotedTable( Schema::grantTable() );
		$authorized = time() - 120 * DAY_IN_SECONDS;
		$result     = $database->execute_query(
			"INSERT INTO {$table}
			(issuer,resource,client_id,client_digest,redirect_uri,user_id,scope,continuing_access,status,authorized_at,last_used_at,refresh_absolute_expires_at,refresh_inactivity_expires_at,client_metadata_fingerprint,revoked_at,revocation_reason)
			VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
			array( $this->issuer, $this->issuer, $clientId, self::clientDigest( $this->issuer, $clientId ), self::REDIRECT, 1, AuthorizationService::GENERAL_SCOPE, $continuingAccess ? 1 : 0, $status, $authorized, $authorized, $refreshExpiresAt, $refreshExpiresAt, '', $revokedAt, $reason )
		); // phpcs:ignore WordPress.DB.RestrictedFunctions.mysql_mysqli -- Test fixtures use the production-owned transaction boundary.
		if ( true !== $result || $database->insert_id <= 0 ) {
			throw new RuntimeException( 'charter_cleanup_fixture_grant_failed' );
		}

		return (int) $database->insert_id;
	}

	/**
	 * Inserts one dynamic registration fixture.
	 *
	 * @param mysqli   $database Owned connection.
	 * @param string   $clientId Exact fixture client.
	 * @param int      $createdAt Creation timestamp.
	 * @param int      $lastActivityAt Activity timestamp.
	 * @param int|null $authorizedAt Optional first authorization timestamp.
	 * @throws RuntimeException When fixture insertion fails.
	 */
	private function insertClient( mysqli $database, string $clientId, int $createdAt, int $lastActivityAt, ?int $authorizedAt ): void {
		$table  = self::quotedTable( Schema::clientTable() );
		$result = $database->execute_query(
			"INSERT INTO {$table}
			(issuer_digest,client_digest,issuer,client_id,client_name,redirect_uris,status,source,token_endpoint_auth_method,grant_types,client_secret_hash,metadata_fingerprint,created_at,last_activity_at,authorized_at,blocked_at,deleted_at)
			VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
			array( self::issuerDigest( $this->issuer ), self::clientDigest( $this->issuer, $clientId ), $this->issuer, $clientId, 'Retention fixture', wp_json_encode( array( self::REDIRECT ) ), 'active', 'dynamic', 'none', 'authorization_code', null, '', $createdAt, $lastActivityAt, $authorizedAt, null, null )
		); // phpcs:ignore WordPress.DB.RestrictedFunctions.mysql_mysqli -- Test fixtures use the production-owned transaction boundary.
		if ( true !== $result ) {
			throw new RuntimeException( 'charter_cleanup_fixture_client_failed' );
		}
	}

	/**
	 * Inserts one audit fixture.
	 *
	 * @param mysqli $database Owned connection.
	 * @param string $reason Stable fixture reason.
	 * @param int    $timestamp Event timestamp.
	 * @throws RuntimeException When fixture insertion fails.
	 */
	private function insertAudit( mysqli $database, string $reason, int $timestamp ): void {
		$table  = self::quotedTable( Schema::auditTable() );
		$result = $database->execute_query(
			"INSERT INTO {$table} (occurred_at,issuer_digest,issuer,event_type,outcome,reason) VALUES (?,?,?,?,?,?)",
			array( $timestamp, self::issuerDigest( $this->issuer ), $this->issuer, 'fixture_event', 'success', $reason )
		); // phpcs:ignore WordPress.DB.RestrictedFunctions.mysql_mysqli -- Test fixtures use the production-owned transaction boundary.
		if ( true !== $result ) {
			throw new RuntimeException( 'charter_cleanup_fixture_audit_failed' );
		}
	}

	/**
	 * Counts one exact credential marker.
	 *
	 * @param string $marker Unique fixture marker.
	 */
	private function countCredential( string $marker ): int {
		return $this->countValue( Schema::credentialTable(), 'digest', hash( 'sha256', $marker ) );
	}

	/**
	 * Counts one exact client identifier.
	 *
	 * @param string $clientId Exact client identifier.
	 */
	private function countClient( string $clientId ): int {
		return $this->countValue( Schema::clientTable(), 'client_id', $clientId );
	}

	/**
	 * Counts one exact retained grant reason.
	 *
	 * @param string $reason Stable reason.
	 */
	private function countGrantReason( string $reason ): int {
		return $this->countValue( Schema::grantTable(), 'revocation_reason', $reason );
	}

	/**
	 * Counts one exact audit reason.
	 *
	 * @param string $reason Stable reason.
	 */
	private function countAuditReason( string $reason ): int {
		return $this->countValue( Schema::auditTable(), 'reason', $reason );
	}

	/**
	 * Counts one test fixture through an owned current-site query.
	 *
	 * @param string $tableName Trusted table name.
	 * @param string $column Trusted fixture column.
	 * @param string $value Exact marker.
	 */
	private function countValue( string $tableName, string $column, string $value ): int {
		return ( new TransactionManager() )->run(
			static function ( mysqli $database ) use ( $tableName, $column, $value ): int {
				$table  = self::quotedTable( $tableName );
				$result = $database->execute_query( "SELECT COUNT(*) AS fixture_count FROM {$table} WHERE {$column} = ?", array( $value ) ); // phpcs:ignore WordPress.DB.RestrictedFunctions.mysql_mysqli,WordPress.DB.PreparedSQL.InterpolatedNotPrepared -- Test-only trusted table and column names with a bound marker.
				if ( ! $result instanceof \mysqli_result ) {
					throw new RuntimeException( 'charter_cleanup_fixture_count_failed' );
				}
				$row = $result->fetch_assoc();
				$result->free();
				$count = is_array( $row ) ? $row['fixture_count'] ?? null : null;

				return is_int( $count ) ? $count : ( is_string( $count ) && ctype_digit( $count ) ? (int) $count : 0 );
			}
		);
	}

	/**
	 * Returns an indexed non-secret issuer reference.
	 *
	 * @param string $issuer Exact issuer.
	 */
	private static function issuerDigest( string $issuer ): string {
		return hash( 'sha256', 'issuer:' . strlen( $issuer ) . ':' . $issuer );
	}

	/**
	 * Returns an indexed non-secret client reference.
	 *
	 * @param string $issuer Exact issuer.
	 * @param string $clientId Exact client identifier.
	 */
	private static function clientDigest( string $issuer, string $clientId ): string {
		return hash( 'sha256', strlen( $issuer ) . ':' . $issuer . strlen( $clientId ) . ':' . $clientId );
	}

	/**
	 * Quotes one trusted WordPress-derived table identifier.
	 *
	 * @param string $table Table identifier.
	 * @throws RuntimeException When the identifier is invalid.
	 */
	private static function quotedTable( string $table ): string {
		if ( 1 !== preg_match( '/^[A-Za-z0-9_]+$/D', $table ) ) {
			throw new RuntimeException( 'charter_cleanup_fixture_table_invalid' );
		}

		return '`' . $table . '`';
	}
}
