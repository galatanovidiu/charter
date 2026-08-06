<?php
/**
 * Issuer-local OAuth retention cleanup.
 *
 * @package GalatanOvidiu\Charter
 */

declare(strict_types=1);

namespace GalatanOvidiu\Charter\OAuth;

use GalatanOvidiu\Charter\Schema;
use mysqli;
use mysqli_result;
use RuntimeException;

/**
 * Deletes only records whose authoritative retention windows have closed.
 *
 * Cleanup remains independent of credential validation. Every query also uses
 * the exact issuer even though Multisite already provides separate tables.
 *
 * @since 0.1.0
 */
final class RetentionCleanup {

	private const SHORT_RETENTION           = 86400;
	private const REFRESH_RETENTION         = 2592000;
	private const HISTORY_RETENTION         = 7776000;
	private const UNUSED_CLIENT_RETENTION   = 604800;
	private const INACTIVE_CLIENT_RETENTION = 7776000;

	/**
	 * Owned non-reconnecting transaction service.
	 *
	 * @var TransactionManager
	 */
	private readonly TransactionManager $transactions;

	/**
	 * Creates the retention engine.
	 *
	 * @param TransactionManager|null $transactions Owned transaction service.
	 */
	public function __construct( ?TransactionManager $transactions = null ) {
		$this->transactions = $transactions ?? new TransactionManager();
	}

	/**
	 * Deletes at most one bounded batch for one exact current-site issuer.
	 *
	 * @param string $issuer Exact prepared site issuer.
	 * @param int    $timestamp Current Unix timestamp.
	 * @param int    $limit Maximum records deleted across every category.
	 * @throws RuntimeException When cleanup input or persistence fails.
	 */
	public function runBatch( string $issuer, int $timestamp, int $limit = 100 ): CleanupBatchResult {
		if ( '' === $issuer || $timestamp < 0 ) {
			throw new RuntimeException( 'charter_cleanup_input_invalid' );
		}
		$limit = max( 1, min( 100, $limit ) );

		return $this->transactions->run(
			function ( mysqli $database ) use ( $issuer, $timestamp, $limit ): CleanupBatchResult {
				$deleted   = self::emptyCounts();
				$remaining = $limit;

				$categories = array(
					'transactions'    => fn ( int $categoryLimit ): int => $this->deleteShortLivedCredentials( $database, $issuer, CredentialStore::AUTHORIZATION_REQUEST, $timestamp - self::SHORT_RETENTION, $categoryLimit, true ),
					'codes'           => fn ( int $categoryLimit ): int => $this->deleteShortLivedCredentials( $database, $issuer, CredentialStore::AUTHORIZATION_CODE, $timestamp - self::SHORT_RETENTION, $categoryLimit, false ),
					'access_tokens'   => fn ( int $categoryLimit ): int => $this->deleteShortLivedCredentials( $database, $issuer, CredentialStore::ACCESS_TOKEN, $timestamp - self::SHORT_RETENTION, $categoryLimit, false ),
					'refresh_tokens'  => fn ( int $categoryLimit ): int => $this->deleteClosedRefreshRecords( $database, $issuer, $timestamp - self::REFRESH_RETENTION, $categoryLimit ),
					'dynamic_clients' => fn ( int $categoryLimit ): int => $this->deleteStaleDynamicClients( $database, $issuer, $timestamp, $categoryLimit ),
					'grants'          => fn ( int $categoryLimit ): int => $this->deleteTerminalGrants( $database, $issuer, $timestamp - self::HISTORY_RETENTION, $categoryLimit ),
					'audit_events'    => fn ( int $categoryLimit ): int => $this->deleteAuditEvents( $database, $issuer, $timestamp - self::HISTORY_RETENTION, $categoryLimit ),
				);

				foreach ( $categories as $category => $delete ) {
					if ( 0 === $remaining ) {
						break;
					}
					$count                = $delete( $remaining );
					$deleted[ $category ] = $count;
					$remaining           -= $count;
				}

				$hasMore = array_sum( $deleted ) === $limit && $this->hasEligibleRecord( $database, $issuer, $timestamp );

				return new CleanupBatchResult( $deleted, $hasMore );
			}
		);
	}

	/**
	 * Deletes expired authorization transactions or terminal short credentials.
	 *
	 * @param mysqli $database Owned connection.
	 * @param string $issuer Exact issuer.
	 * @param string $type Credential type.
	 * @param int    $cutoff Inclusive retention cutoff.
	 * @param int    $limit Remaining batch capacity.
	 * @param bool   $byCreation Whether the transaction retention begins at creation.
	 */
	private function deleteShortLivedCredentials( mysqli $database, string $issuer, string $type, int $cutoff, int $limit, bool $byCreation ): int {
		$table      = self::quotedTable( Schema::credentialTable() );
		$condition  = $byCreation
			? 'created_at <= ?'
			: '((consumed_at IS NOT NULL AND consumed_at <= ?) OR (consumed_at IS NULL AND expires_at <= ?))';
		$parameters = $byCreation ? array( $issuer, $type, $cutoff ) : array( $issuer, $type, $cutoff, $cutoff );
		$ids        = $this->selectIds(
			$database,
			"SELECT id FROM {$table} WHERE issuer = ? AND credential_type = ? AND {$condition} ORDER BY id ASC LIMIT {$limit}",
			$parameters
		);

		return $this->deleteIds( $database, $table, $issuer, $ids );
	}

	/**
	 * Deletes refresh lineage only after its complete family retention closes.
	 *
	 * @param mysqli $database Owned connection.
	 * @param string $issuer Exact issuer.
	 * @param int    $cutoff Inclusive retention cutoff.
	 * @param int    $limit Remaining batch capacity.
	 */
	private function deleteClosedRefreshRecords( mysqli $database, string $issuer, int $cutoff, int $limit ): int {
		$credentials = self::quotedTable( Schema::credentialTable() );
		$grants      = self::quotedTable( Schema::grantTable() );
		$ids         = $this->selectIds(
			$database,
			"SELECT credential.id FROM {$credentials} credential
			INNER JOIN {$grants} grant_record ON grant_record.id = credential.grant_id
			WHERE credential.issuer = ? AND credential.credential_type = ? AND grant_record.issuer = ?
			AND (
				(grant_record.status IN ('revoked','expired') AND grant_record.revoked_at IS NOT NULL AND grant_record.revoked_at <= ?)
				OR (
					grant_record.status = 'active' AND grant_record.continuing_access = 1
					AND grant_record.refresh_absolute_expires_at IS NOT NULL
					AND grant_record.refresh_inactivity_expires_at IS NOT NULL
					AND LEAST(grant_record.refresh_absolute_expires_at, grant_record.refresh_inactivity_expires_at) <= ?
				)
			)
			ORDER BY credential.id ASC LIMIT {$limit}",
			array( $issuer, CredentialStore::REFRESH_TOKEN, $issuer, $cutoff, $cutoff )
		);

		return $this->deleteIds( $database, $credentials, $issuer, $ids );
	}

	/**
	 * Deletes stale DCR registrations only without an authoritative active grant.
	 *
	 * @param mysqli $database Owned connection.
	 * @param string $issuer Exact issuer.
	 * @param int    $timestamp Current Unix timestamp.
	 * @param int    $limit Remaining batch capacity.
	 */
	private function deleteStaleDynamicClients( mysqli $database, string $issuer, int $timestamp, int $limit ): int {
		$clients = self::quotedTable( Schema::clientTable() );
		$grants  = self::quotedTable( Schema::grantTable() );
		$ids     = $this->selectIds(
			$database,
			"SELECT client.id FROM {$clients} client
			WHERE client.issuer_digest = ? AND client.issuer = ? AND client.source = ? AND client.status = ?
			AND (
				(client.authorized_at IS NULL AND client.created_at <= ?)
				OR (client.authorized_at IS NOT NULL AND client.last_activity_at <= ?)
			)
			AND NOT EXISTS (
				SELECT 1 FROM {$grants} grant_record
				WHERE grant_record.client_digest = client.client_digest AND grant_record.issuer = ? AND grant_record.status = 'active'
				AND (
					grant_record.continuing_access = 0
					OR (grant_record.refresh_absolute_expires_at > ? AND grant_record.refresh_inactivity_expires_at > ?)
				)
			)
			ORDER BY client.id ASC LIMIT {$limit}",
			array(
				self::issuerDigest( $issuer ),
				$issuer,
				ClientRegistry::SOURCE_DYNAMIC,
				ClientRegistry::STATUS_ACTIVE,
				$timestamp - self::UNUSED_CLIENT_RETENTION,
				$timestamp - self::INACTIVE_CLIENT_RETENTION,
				$issuer,
				$timestamp,
				$timestamp,
			)
		);

		return $this->deleteIds( $database, $clients, $issuer, $ids );
	}

	/**
	 * Deletes retained terminal grant history only after descendants are gone.
	 *
	 * @param mysqli $database Owned connection.
	 * @param string $issuer Exact issuer.
	 * @param int    $cutoff Inclusive retention cutoff.
	 * @param int    $limit Remaining batch capacity.
	 */
	private function deleteTerminalGrants( mysqli $database, string $issuer, int $cutoff, int $limit ): int {
		$grants      = self::quotedTable( Schema::grantTable() );
		$credentials = self::quotedTable( Schema::credentialTable() );
		$ids         = $this->selectIds(
			$database,
			"SELECT grant_record.id FROM {$grants} grant_record
			WHERE grant_record.issuer = ? AND (
				(grant_record.status IN ('revoked','expired') AND grant_record.revoked_at IS NOT NULL AND grant_record.revoked_at <= ?)
				OR (
					grant_record.status = 'active' AND grant_record.continuing_access = 1
					AND grant_record.refresh_absolute_expires_at IS NOT NULL
					AND grant_record.refresh_inactivity_expires_at IS NOT NULL
					AND LEAST(grant_record.refresh_absolute_expires_at, grant_record.refresh_inactivity_expires_at) <= ?
				)
			)
			AND NOT EXISTS (SELECT 1 FROM {$credentials} credential WHERE credential.grant_id = grant_record.id)
			ORDER BY grant_record.id ASC LIMIT {$limit}",
			array( $issuer, $cutoff, $cutoff )
		);

		return $this->deleteIds( $database, $grants, $issuer, $ids );
	}

	/**
	 * Deletes issuer-local security history after its 90-day window.
	 *
	 * @param mysqli $database Owned connection.
	 * @param string $issuer Exact issuer.
	 * @param int    $cutoff Inclusive retention cutoff.
	 * @param int    $limit Remaining batch capacity.
	 */
	private function deleteAuditEvents( mysqli $database, string $issuer, int $cutoff, int $limit ): int {
		$table = self::quotedTable( Schema::auditTable() );
		$ids   = $this->selectIds(
			$database,
			"SELECT id FROM {$table} WHERE issuer_digest = ? AND issuer = ? AND occurred_at <= ? ORDER BY id ASC LIMIT {$limit}",
			array( self::issuerDigest( $issuer ), $issuer, $cutoff )
		);

		return $this->deleteIds( $database, $table, $issuer, $ids );
	}

	/**
	 * Reports whether any category remains eligible after a full batch.
	 *
	 * @param mysqli $database Owned connection.
	 * @param string $issuer Exact issuer.
	 * @param int    $timestamp Current Unix timestamp.
	 */
	private function hasEligibleRecord( mysqli $database, string $issuer, int $timestamp ): bool {
		$probes = array(
			fn (): int => $this->countShortLivedCredential( $database, $issuer, CredentialStore::AUTHORIZATION_REQUEST, $timestamp - self::SHORT_RETENTION, true ),
			fn (): int => $this->countShortLivedCredential( $database, $issuer, CredentialStore::AUTHORIZATION_CODE, $timestamp - self::SHORT_RETENTION, false ),
			fn (): int => $this->countShortLivedCredential( $database, $issuer, CredentialStore::ACCESS_TOKEN, $timestamp - self::SHORT_RETENTION, false ),
			fn (): int => $this->countClosedRefreshRecord( $database, $issuer, $timestamp - self::REFRESH_RETENTION ),
			fn (): int => $this->countStaleDynamicClient( $database, $issuer, $timestamp ),
			fn (): int => $this->countTerminalGrant( $database, $issuer, $timestamp - self::HISTORY_RETENTION ),
			fn (): int => $this->countAuditEvent( $database, $issuer, $timestamp - self::HISTORY_RETENTION ),
		);
		foreach ( $probes as $probe ) {
			if ( 0 < $probe() ) {
				return true;
			}
		}

		return false;
	}

	/**
	 * Returns one when a short-lived credential is eligible.
	 *
	 * @param mysqli $database Owned connection.
	 * @param string $issuer Exact issuer.
	 * @param string $type Credential type.
	 * @param int    $cutoff Inclusive retention cutoff.
	 * @param bool   $byCreation Whether retention begins at creation.
	 */
	private function countShortLivedCredential( mysqli $database, string $issuer, string $type, int $cutoff, bool $byCreation ): int {
		$table      = self::quotedTable( Schema::credentialTable() );
		$condition  = $byCreation ? 'created_at <= ?' : '((consumed_at IS NOT NULL AND consumed_at <= ?) OR (consumed_at IS NULL AND expires_at <= ?))';
		$parameters = $byCreation ? array( $issuer, $type, $cutoff ) : array( $issuer, $type, $cutoff, $cutoff );

		return $this->exists( $database, "SELECT id FROM {$table} WHERE issuer = ? AND credential_type = ? AND {$condition} LIMIT 1", $parameters );
	}

	/**
	 * Returns one when closed refresh lineage remains eligible.
	 *
	 * @param mysqli $database Owned connection.
	 * @param string $issuer Exact issuer.
	 * @param int    $cutoff Inclusive retention cutoff.
	 */
	private function countClosedRefreshRecord( mysqli $database, string $issuer, int $cutoff ): int {
		$credentials = self::quotedTable( Schema::credentialTable() );
		$grants      = self::quotedTable( Schema::grantTable() );

		return $this->exists(
			$database,
			"SELECT credential.id FROM {$credentials} credential INNER JOIN {$grants} grant_record ON grant_record.id = credential.grant_id
			WHERE credential.issuer = ? AND credential.credential_type = ? AND grant_record.issuer = ?
			AND ((grant_record.status IN ('revoked','expired') AND grant_record.revoked_at IS NOT NULL AND grant_record.revoked_at <= ?)
			OR (grant_record.status = 'active' AND grant_record.continuing_access = 1
			AND grant_record.refresh_absolute_expires_at IS NOT NULL AND grant_record.refresh_inactivity_expires_at IS NOT NULL
			AND LEAST(grant_record.refresh_absolute_expires_at, grant_record.refresh_inactivity_expires_at) <= ?)) LIMIT 1",
			array( $issuer, CredentialStore::REFRESH_TOKEN, $issuer, $cutoff, $cutoff )
		);
	}

	/**
	 * Returns one when a stale dynamic client remains eligible.
	 *
	 * @param mysqli $database Owned connection.
	 * @param string $issuer Exact issuer.
	 * @param int    $timestamp Current Unix timestamp.
	 */
	private function countStaleDynamicClient( mysqli $database, string $issuer, int $timestamp ): int {
		$clients = self::quotedTable( Schema::clientTable() );
		$grants  = self::quotedTable( Schema::grantTable() );

		return $this->exists(
			$database,
			"SELECT client.id FROM {$clients} client WHERE client.issuer_digest = ? AND client.issuer = ? AND client.source = ? AND client.status = ?
			AND ((client.authorized_at IS NULL AND client.created_at <= ?) OR (client.authorized_at IS NOT NULL AND client.last_activity_at <= ?))
			AND NOT EXISTS (SELECT 1 FROM {$grants} grant_record WHERE grant_record.client_digest = client.client_digest
			AND grant_record.issuer = ? AND grant_record.status = 'active'
			AND (grant_record.continuing_access = 0 OR (grant_record.refresh_absolute_expires_at > ? AND grant_record.refresh_inactivity_expires_at > ?))) LIMIT 1",
			array(
				self::issuerDigest( $issuer ),
				$issuer,
				ClientRegistry::SOURCE_DYNAMIC,
				ClientRegistry::STATUS_ACTIVE,
				$timestamp - self::UNUSED_CLIENT_RETENTION,
				$timestamp - self::INACTIVE_CLIENT_RETENTION,
				$issuer,
				$timestamp,
				$timestamp,
			)
		);
	}

	/**
	 * Returns one when terminal grant history remains eligible.
	 *
	 * @param mysqli $database Owned connection.
	 * @param string $issuer Exact issuer.
	 * @param int    $cutoff Inclusive retention cutoff.
	 */
	private function countTerminalGrant( mysqli $database, string $issuer, int $cutoff ): int {
		$grants      = self::quotedTable( Schema::grantTable() );
		$credentials = self::quotedTable( Schema::credentialTable() );

		return $this->exists(
			$database,
			"SELECT grant_record.id FROM {$grants} grant_record WHERE grant_record.issuer = ?
			AND ((grant_record.status IN ('revoked','expired') AND grant_record.revoked_at IS NOT NULL AND grant_record.revoked_at <= ?)
			OR (grant_record.status = 'active' AND grant_record.continuing_access = 1
			AND grant_record.refresh_absolute_expires_at IS NOT NULL AND grant_record.refresh_inactivity_expires_at IS NOT NULL
			AND LEAST(grant_record.refresh_absolute_expires_at, grant_record.refresh_inactivity_expires_at) <= ?))
			AND NOT EXISTS (SELECT 1 FROM {$credentials} credential WHERE credential.grant_id = grant_record.id) LIMIT 1",
			array( $issuer, $cutoff, $cutoff )
		);
	}

	/**
	 * Returns one when retained audit history remains eligible.
	 *
	 * @param mysqli $database Owned connection.
	 * @param string $issuer Exact issuer.
	 * @param int    $cutoff Inclusive retention cutoff.
	 */
	private function countAuditEvent( mysqli $database, string $issuer, int $cutoff ): int {
		$table = self::quotedTable( Schema::auditTable() );

		return $this->exists(
			$database,
			"SELECT id FROM {$table} WHERE issuer_digest = ? AND issuer = ? AND occurred_at <= ? LIMIT 1",
			array( self::issuerDigest( $issuer ), $issuer, $cutoff )
		);
	}

	/**
	 * Selects integer identifiers from one bounded query.
	 *
	 * @param mysqli       $database Owned connection.
	 * @param string       $sql Complete trusted query.
	 * @param array<mixed> $parameters Bound scalar parameters.
	 * @return array<int>
	 * @throws RuntimeException When selection fails.
	 */
	private function selectIds( mysqli $database, string $sql, array $parameters ): array {
		$result = $database->execute_query( $sql, $parameters ); // phpcs:ignore WordPress.DB.RestrictedFunctions.mysql_mysqli,WordPress.DB.PreparedSQL.NotPrepared -- Cleanup SQL uses trusted tables and clamped LIMIT literals on an owned connection.
		if ( ! $result instanceof mysqli_result ) {
			throw new RuntimeException( 'charter_cleanup_query_failed' );
		}
		$ids = array();
		while ( true ) {
			$row = $result->fetch_assoc();
			if ( ! is_array( $row ) ) {
				break;
			}
			$id = self::integerValue( $row['id'] ?? null );
			if ( is_int( $id ) && 0 < $id ) {
				$ids[] = $id;
			}
		}
		$result->free();

		return $ids;
	}

	/**
	 * Deletes selected identifiers while reasserting the exact issuer boundary.
	 *
	 * @param mysqli     $database Owned connection.
	 * @param string     $table Trusted quoted table.
	 * @param string     $issuer Exact issuer.
	 * @param array<int> $ids Selected record identifiers.
	 * @throws RuntimeException When deletion fails.
	 */
	private function deleteIds( mysqli $database, string $table, string $issuer, array $ids ): int {
		if ( array() === $ids ) {
			return 0;
		}
		$placeholders = implode( ',', array_fill( 0, count( $ids ), '?' ) );
		$result       = $database->execute_query(
			"DELETE FROM {$table} WHERE issuer = ? AND id IN ({$placeholders})",
			array_merge( array( $issuer ), $ids )
		); // phpcs:ignore WordPress.DB.RestrictedFunctions.mysql_mysqli,WordPress.DB.PreparedSQL.InterpolatedNotPrepared -- Trusted table and generated placeholders; issuer and identifiers remain bound.
		if ( true !== $result ) {
			throw new RuntimeException( 'charter_cleanup_delete_failed' );
		}

		$count = self::integerValue( $database->affected_rows );
		if ( null === $count ) {
			throw new RuntimeException( 'charter_cleanup_count_invalid' );
		}

		return $count;
	}

	/**
	 * Returns one when a trusted eligibility query has a row.
	 *
	 * @param mysqli       $database Owned connection.
	 * @param string       $sql Trusted eligibility query.
	 * @param array<mixed> $parameters Bound scalar parameters.
	 * @throws RuntimeException When selection fails.
	 */
	private function exists( mysqli $database, string $sql, array $parameters ): int {
		$result = $database->execute_query( $sql, $parameters ); // phpcs:ignore WordPress.DB.RestrictedFunctions.mysql_mysqli,WordPress.DB.PreparedSQL.NotPrepared -- Trusted bounded eligibility query on an owned connection.
		if ( ! $result instanceof mysqli_result ) {
			throw new RuntimeException( 'charter_cleanup_query_failed' );
		}
		$exists = 0 < $result->num_rows ? 1 : 0;
		$result->free();

		return $exists;
	}

	/**
	 * Returns stable zero counts for every retention category.
	 *
	 * @return array{transactions:int,codes:int,access_tokens:int,refresh_tokens:int,dynamic_clients:int,grants:int,audit_events:int}
	 */
	private static function emptyCounts(): array {
		return array(
			'transactions'    => 0,
			'codes'           => 0,
			'access_tokens'   => 0,
			'refresh_tokens'  => 0,
			'dynamic_clients' => 0,
			'grants'          => 0,
			'audit_events'    => 0,
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
	 * Converts one database integer.
	 *
	 * @param mixed $value Database value.
	 */
	private static function integerValue( mixed $value ): ?int {
		return is_int( $value ) && 0 <= $value ? $value : ( is_string( $value ) && ctype_digit( $value ) ? (int) $value : null );
	}

	/**
	 * Quotes one trusted WordPress-derived table identifier.
	 *
	 * @param string $table Table identifier.
	 * @throws RuntimeException When the identifier is invalid.
	 */
	private static function quotedTable( string $table ): string {
		if ( 1 !== preg_match( '/^[A-Za-z0-9_]+$/D', $table ) ) {
			throw new RuntimeException( 'charter_database_table_invalid' );
		}

		return '`' . $table . '`';
	}
}
