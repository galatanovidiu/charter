<?php
/**
 * Disposable Slice 0 atomic-lifecycle proof schema.
 *
 * @package GalatanOvidiu\Charter
 */

declare(strict_types=1);

namespace GalatanOvidiu\Charter\Tests\Prototype\AtomicLifecycle;

use mysqli;
use mysqli_result;
use RuntimeException;

/**
 * Owns provisional DDL that must never become a production schema.
 *
 * @since 0.1.0
 */
final class AtomicLifecycleSchema {

	public const GRANTS = 'charter_p1_proof_grants';

	public const CODES = 'charter_p1_proof_codes';

	public const FAMILIES = 'charter_p1_proof_refresh_families';

	public const MEMBERS = 'charter_p1_proof_refresh_members';

	public const ACCESS = 'charter_p1_proof_access';

	public const EVENTS = 'charter_p1_proof_events';

	public const SENTINELS = 'charter_p1_proof_sentinels';

	/**
	 * Creates every provisional InnoDB proof table outside behavior transactions.
	 *
	 * @param mysqli $database Disposable database connection.
	 * @throws RuntimeException When DDL or capability validation fails.
	 */
	public static function create( mysqli $database ): void {
		foreach ( self::definitions() as $definition ) {
			if ( true !== $database->query( $definition ) ) {
				throw new RuntimeException( 'atomic_lifecycle_schema_create_failed' );
			}
		}

		$capabilities = self::capabilities( $database );

		if (
			! $capabilities['tables_present']
			|| ! $capabilities['all_innodb']
			|| ! $capabilities['unique_invariants_present']
		) {
			throw new RuntimeException( 'atomic_lifecycle_schema_capability_failed' );
		}
	}

	/**
	 * Drops only the exact provisional proof tables in dependency-safe order.
	 *
	 * @param mysqli $database Disposable database connection.
	 * @throws RuntimeException When an exact proof table cannot be dropped.
	 */
	public static function drop( mysqli $database ): void {
		foreach ( array_reverse( self::tableNames() ) as $table ) {
			if ( true !== $database->query( "DROP TABLE IF EXISTS {$table}" ) ) {
				throw new RuntimeException( 'atomic_lifecycle_schema_drop_failed' );
			}
		}
	}

	/**
	 * Returns the fixed disposable table allowlist.
	 *
	 * @return list<string>
	 */
	public static function tableNames(): array {
		return array(
			self::GRANTS,
			self::CODES,
			self::FAMILIES,
			self::MEMBERS,
			self::ACCESS,
			self::EVENTS,
			self::SENTINELS,
		);
	}

	/**
	 * Returns sanitized storage-engine and invariant evidence.
	 *
	 * @param mysqli $database Disposable database connection.
	 * @return array{tables_present: bool, table_count: int, all_innodb: bool, unique_invariants_present: bool}
	 * @throws RuntimeException When schema metadata cannot be read safely.
	 */
	public static function capabilities( mysqli $database ): array {
		$placeholders = implode( ', ', array_fill( 0, count( self::tableNames() ), '?' ) );
		$tablesResult = $database->execute_query(
			"SELECT TABLE_NAME, ENGINE FROM information_schema.TABLES WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME IN ({$placeholders})",
			self::tableNames()
		);

		if ( ! $tablesResult instanceof mysqli_result ) {
			throw new RuntimeException( 'atomic_lifecycle_schema_inspection_failed' );
		}

		$engines = array();

		$row = $tablesResult->fetch_assoc();

		while ( is_array( $row ) ) {
			$tableName = $row['TABLE_NAME'] ?? null;
			$engine    = $row['ENGINE'] ?? null;

			if ( ! is_string( $tableName ) || ! is_string( $engine ) ) {
				throw new RuntimeException( 'atomic_lifecycle_schema_metadata_invalid' );
			}

			$engines[ $tableName ] = strtolower( $engine );
			$row                   = $tablesResult->fetch_assoc();
		}

		$tablesResult->free();
		$requiredIndexes = array(
			'p1_unique_code_lineage',
			'p1_unique_family_for_code',
			'p1_unique_family_generation',
			'p1_unique_refresh_child',
			'p1_unique_access_issuance',
		);
		$indexHolders    = array(
			self::CODES,
			self::FAMILIES,
			self::MEMBERS,
			self::ACCESS,
		);
		$index_tables    = implode( ', ', array_fill( 0, count( $indexHolders ), '?' ) );
		$index_names     = implode( ', ', array_fill( 0, count( $requiredIndexes ), '?' ) );
		$indexResult     = $database->execute_query(
			"SELECT DISTINCT INDEX_NAME FROM information_schema.STATISTICS WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME IN ({$index_tables}) AND NON_UNIQUE = 0 AND INDEX_NAME IN ({$index_names})",
			array_merge( $indexHolders, $requiredIndexes )
		);

		if ( ! $indexResult instanceof mysqli_result ) {
			throw new RuntimeException( 'atomic_lifecycle_index_inspection_failed' );
		}

		$foundIndexes = array();

		$row = $indexResult->fetch_assoc();

		while ( is_array( $row ) ) {
			$indexName = $row['INDEX_NAME'] ?? null;

			if ( ! is_string( $indexName ) ) {
				throw new RuntimeException( 'atomic_lifecycle_index_metadata_invalid' );
			}

			$foundIndexes[] = $indexName;
			$row            = $indexResult->fetch_assoc();
		}

		$indexResult->free();

		return array(
			'tables_present'            => count( $engines ) === count( self::tableNames() ),
			'table_count'               => count( $engines ),
			'all_innodb'                => count( $engines ) === count( self::tableNames() )
				&& array() === array_diff( array_values( $engines ), array( 'innodb' ) ),
			'unique_invariants_present' => array() === array_diff( $requiredIndexes, $foundIndexes ),
		);
	}

	/**
	 * Returns the exact provisional DDL statements.
	 *
	 * @return list<string>
	 */
	private static function definitions(): array {
		$options = 'ENGINE=InnoDB DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_bin';

		return array(
			'CREATE TABLE ' . self::GRANTS . " (
				grant_id VARCHAR(64) NOT NULL,
				issuer VARCHAR(255) NOT NULL,
				resource_id VARCHAR(255) NOT NULL,
				client_id VARCHAR(128) NOT NULL,
				user_id BIGINT UNSIGNED NOT NULL,
				scope_value VARCHAR(255) NOT NULL,
				state VARCHAR(24) NOT NULL,
				inactivity_expires_at BIGINT UNSIGNED NOT NULL,
				absolute_expires_at BIGINT UNSIGNED NOT NULL,
				PRIMARY KEY (grant_id)
			) {$options}",
			'CREATE TABLE ' . self::CODES . " (
				code_digest CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
				code_id VARCHAR(64) NOT NULL,
				grant_id VARCHAR(64) NOT NULL,
				state VARCHAR(24) NOT NULL,
				lineage_id VARCHAR(64) NULL,
				expires_at BIGINT UNSIGNED NOT NULL,
				replay_event_count INT UNSIGNED NOT NULL DEFAULT 0,
				PRIMARY KEY (code_digest),
				UNIQUE KEY p1_unique_code_id (code_id),
				UNIQUE KEY p1_unique_code_lineage (lineage_id),
				KEY p1_code_grant (grant_id)
			) {$options}",
			'CREATE TABLE ' . self::FAMILIES . " (
				family_id VARCHAR(64) NOT NULL,
				grant_id VARCHAR(64) NOT NULL,
				code_id VARCHAR(64) NULL,
				state VARCHAR(24) NOT NULL,
				current_generation INT UNSIGNED NOT NULL,
				inactivity_expires_at BIGINT UNSIGNED NOT NULL,
				absolute_expires_at BIGINT UNSIGNED NOT NULL,
				PRIMARY KEY (family_id),
				UNIQUE KEY p1_unique_family_for_code (code_id),
				KEY p1_family_grant (grant_id)
			) {$options}",
			'CREATE TABLE ' . self::MEMBERS . " (
				member_digest CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
				member_id VARCHAR(64) NOT NULL,
				family_id VARCHAR(64) NOT NULL,
				generation INT UNSIGNED NOT NULL,
				parent_digest CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NULL,
				state VARCHAR(24) NOT NULL,
				PRIMARY KEY (member_digest),
				UNIQUE KEY p1_unique_member_id (member_id),
				UNIQUE KEY p1_unique_family_generation (family_id, generation),
				UNIQUE KEY p1_unique_refresh_child (parent_digest),
				KEY p1_member_family_state (family_id, state)
			) {$options}",
			'CREATE TABLE ' . self::ACCESS . " (
				access_digest CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
				access_id VARCHAR(64) NOT NULL,
				issuance_key VARCHAR(96) NOT NULL,
				grant_id VARCHAR(64) NOT NULL,
				code_id VARCHAR(64) NULL,
				family_id VARCHAR(64) NULL,
				generation INT UNSIGNED NULL,
				state VARCHAR(24) NOT NULL,
				PRIMARY KEY (access_digest),
				UNIQUE KEY p1_unique_access_id (access_id),
				UNIQUE KEY p1_unique_access_issuance (issuance_key),
				KEY p1_access_grant_state (grant_id, state),
				KEY p1_access_code (code_id),
				KEY p1_access_family (family_id)
			) {$options}",
			'CREATE TABLE ' . self::EVENTS . " (
				event_key VARCHAR(96) NOT NULL,
				event_type VARCHAR(32) NOT NULL,
				source_id VARCHAR(64) NOT NULL,
				PRIMARY KEY (event_key),
				KEY p1_event_source (source_id)
			) {$options}",
			'CREATE TABLE ' . self::SENTINELS . " (
				sentinel_id INT UNSIGNED NOT NULL,
				value_number INT NOT NULL,
				PRIMARY KEY (sentinel_id)
			) {$options}",
		);
	}

	/**
	 * This class contains static DDL operations only.
	 */
	private function __construct() {
	}
}
