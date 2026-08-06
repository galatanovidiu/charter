<?php
/**
 * Secret-free OAuth audit persistence.
 *
 * @package GalatanOvidiu\Charter
 */

declare(strict_types=1);

namespace GalatanOvidiu\Charter\Security;

use GalatanOvidiu\Charter\OAuth\TransactionManager;
use GalatanOvidiu\Charter\Schema;
use mysqli;
use mysqli_result;
use RuntimeException;

/**
 * Stores bounded security and lifecycle events, never protocol bodies or credentials.
 *
 * @since 0.1.0
 */
final class AuditLog {

	/**
	 * Owned non-reconnecting transaction service.
	 *
	 * @var TransactionManager
	 */
	private readonly TransactionManager $transactions;

	/**
	 * Creates the audit ledger.
	 *
	 * @param TransactionManager|null $transactions Owned transaction service.
	 */
	public function __construct( ?TransactionManager $transactions = null ) {
		$this->transactions = $transactions ?? new TransactionManager();
	}

	/**
	 * Records one validated event.
	 *
	 * @param string      $issuer Exact issuer.
	 * @param string      $eventType Stable event type.
	 * @param string      $outcome Stable outcome.
	 * @param string      $reason Stable reason.
	 * @param int|null    $actorUserId Acting WordPress user.
	 * @param int|null    $representedUserId Represented user.
	 * @param string|null $clientId Exact client identifier.
	 * @param string|null $sourceAddress Normalized source when security-relevant.
	 * @param int|null    $timestamp Event timestamp.
	 * @param string|null $resourceIdentifier Exact protected resource when applicable.
	 * @param string|null $scopes Canonical scope set when applicable.
	 * @throws RuntimeException When the event or persistence is invalid.
	 */
	public function record( string $issuer, string $eventType, string $outcome, string $reason, ?int $actorUserId = null, ?int $representedUserId = null, ?string $clientId = null, ?string $sourceAddress = null, ?int $timestamp = null, ?string $resourceIdentifier = null, ?string $scopes = null ): void {
		if (
			'' === $issuer
			|| 1 !== preg_match( '/^[a-z0-9_]{1,64}$/D', $eventType )
			|| 1 !== preg_match( '/^[a-z0-9_]{1,32}$/D', $outcome )
			|| 1 !== preg_match( '/^[a-z0-9_]{1,64}$/D', $reason )
			|| ( is_string( $clientId ) && 2048 < strlen( $clientId ) )
			|| ( is_string( $sourceAddress ) && 64 < strlen( $sourceAddress ) )
			|| ( is_string( $resourceIdentifier ) && 2048 < strlen( $resourceIdentifier ) )
			|| ( is_string( $scopes ) && 2048 < strlen( $scopes ) )
		) {
			throw new RuntimeException( 'charter_audit_event_invalid' );
		}
		$occurredAt = $timestamp ?? time();

		$this->transactions->run(
			static function ( mysqli $database ) use ( $issuer, $eventType, $outcome, $reason, $actorUserId, $representedUserId, $clientId, $sourceAddress, $occurredAt, $resourceIdentifier, $scopes ): void {
				$table  = self::quotedTable( Schema::auditTable() );
				$result = $database->execute_query(
					"INSERT INTO {$table} (occurred_at,issuer_digest,issuer,event_type,actor_user_id,represented_user_id,client_id,resource,scopes,outcome,reason,source_address)
					VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
					array( $occurredAt, self::issuerDigest( $issuer ), $issuer, $eventType, $actorUserId, $representedUserId, $clientId, $resourceIdentifier, $scopes, $outcome, $reason, $sourceAddress )
				); // phpcs:ignore WordPress.DB.RestrictedFunctions.mysql_mysqli -- Security ledger uses an owned connection and validated non-secret fields.
				if ( true !== $result || 1 !== $database->affected_rows ) {
					throw new RuntimeException( 'charter_audit_event_failed' );
				}
			}
		);

		if ( function_exists( 'do_action' ) ) {
			do_action(
				'charter_oauth_audit_event_recorded',
				new AuditEvent( $issuer, $occurredAt, $eventType, $actorUserId, $representedUserId, $clientId, $outcome, $reason, $sourceAddress, $resourceIdentifier, $scopes )
			); // phpcs:ignore WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedHooknameFound -- Fixed Charter-prefixed extension action.
		}
	}

	/**
	 * Lists recent events for one site issuer.
	 *
	 * @param string $issuer Exact issuer.
	 * @param int    $limit Maximum events.
	 * @return array<AuditEvent>
	 */
	public function listForIssuer( string $issuer, int $limit = 100 ): array {
		$limit = max( 1, min( 500, $limit ) );
		return $this->transactions->run(
			static function ( mysqli $database ) use ( $issuer, $limit ): array {
				$table  = self::quotedTable( Schema::auditTable() );
				$result = $database->execute_query(
					"SELECT occurred_at,event_type,actor_user_id,represented_user_id,client_id,resource,scopes,outcome,reason,source_address
					FROM {$table} WHERE issuer_digest = ? AND issuer = ? ORDER BY occurred_at DESC, id DESC LIMIT ?",
					array( self::issuerDigest( $issuer ), $issuer, $limit )
				); // phpcs:ignore WordPress.DB.RestrictedFunctions.mysql_mysqli -- Administrator event reads use an owned connection.
				if ( ! $result instanceof mysqli_result ) {
					throw new RuntimeException( 'charter_database_query_failed' );
				}

				$events = array();
				while ( true ) {
					$row = $result->fetch_assoc();
					if ( ! is_array( $row ) ) {
						break;
					}
					$occurredAt = self::integerValue( $row['occurred_at'] ?? null );
					if ( null === $occurredAt || ! is_string( $row['event_type'] ?? null ) || ! is_string( $row['outcome'] ?? null ) || ! is_string( $row['reason'] ?? null ) ) {
						continue;
					}
					$events[] = new AuditEvent(
						$issuer,
						$occurredAt,
						$row['event_type'],
						self::nullableIntegerValue( $row['actor_user_id'] ?? null ),
						self::nullableIntegerValue( $row['represented_user_id'] ?? null ),
						is_string( $row['client_id'] ?? null ) ? $row['client_id'] : null,
						$row['outcome'],
						$row['reason'],
						is_string( $row['source_address'] ?? null ) ? $row['source_address'] : null,
						is_string( $row['resource'] ?? null ) ? $row['resource'] : null,
						is_string( $row['scopes'] ?? null ) ? $row['scopes'] : null
					);
				}
				$result->free();

				return $events;
			}
		);
	}

	/** Deletes current-site events during tests or uninstall. */
	public function deleteAll(): void {
		$this->transactions->run(
			static function ( mysqli $database ): void {
				$table = self::quotedTable( Schema::auditTable() );
				if ( true !== $database->query( "DELETE FROM {$table}" ) ) { // phpcs:ignore WordPress.DB.RestrictedFunctions.mysql_mysqli -- Bounded owned cleanup.
					throw new RuntimeException( 'charter_audit_cleanup_failed' );
				}
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
	 * Converts one database integer.
	 *
	 * @param mixed $value Database value.
	 */
	private static function integerValue( mixed $value ): ?int {
		return is_int( $value ) && 0 <= $value ? $value : ( is_string( $value ) && ctype_digit( $value ) ? (int) $value : null );
	}

	/**
	 * Converts one nullable database integer.
	 *
	 * @param mixed $value Database value.
	 */
	private static function nullableIntegerValue( mixed $value ): ?int {
		return null === $value ? null : self::integerValue( $value );
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
