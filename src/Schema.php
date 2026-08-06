<?php
/**
 * Charter persistence schema.
 *
 * @package GalatanOvidiu\Charter
 */

declare(strict_types=1);

namespace GalatanOvidiu\Charter;

use RuntimeException;

/**
 * Installs the site-scoped OAuth credential table.
 *
 * @since 0.1.0
 */
final class Schema {

	private const VERSION_OPTION = 'charter_oauth_schema_version';
	private const VERSION        = '5';

	/**
	 * Installs the schema only when the current version is absent.
	 *
	 * @since 0.1.0
	 *
	 * @return bool Whether installation ran for this request.
	 */
	public static function maybeInstall(): bool {
		if ( self::VERSION === get_option( self::VERSION_OPTION ) ) {
			return false;
		}

		self::install();

		return true;
	}

	/**
	 * Installs or upgrades the current site's schema.
	 *
	 * @since 0.1.0
	 *
	 * @throws RuntimeException When the schema cannot be installed or verified.
	 */
	public static function install(): void {
		require_once ABSPATH . 'wp-admin/includes/upgrade.php';

		$database     = self::database();
		$table_name   = self::credentialTable();
		$collation    = $database->get_charset_collate();
		$grant_table  = self::grantTable();
		$client_table = self::clientTable();
		$rate_table   = self::rateLimitTable();
		$audit_table  = self::auditTable();
		$cimd_table   = self::clientMetadataTable();
		$sql          = "CREATE TABLE {$table_name} (
			id bigint(20) unsigned NOT NULL AUTO_INCREMENT,
			credential_type varchar(32) NOT NULL,
			digest char(64) NOT NULL,
			issuer text NOT NULL,
			resource text NOT NULL,
			client_id text NOT NULL,
			redirect_uri text NOT NULL,
			user_id bigint(20) unsigned NOT NULL,
			scope text NOT NULL,
			code_challenge varchar(128) NOT NULL DEFAULT '',
			request_state text NULL,
			expires_at bigint(20) unsigned NOT NULL,
			consumed_at bigint(20) unsigned NULL,
			created_at bigint(20) unsigned NOT NULL,
			grant_id bigint(20) unsigned NULL,
			parent_id bigint(20) unsigned NULL,
			continuing_access tinyint(1) unsigned NOT NULL DEFAULT 0,
			client_metadata_fingerprint char(64) NOT NULL DEFAULT '',
			PRIMARY KEY  (id),
			UNIQUE KEY credential (credential_type,digest),
			KEY grant_credentials (grant_id,credential_type,consumed_at,expires_at),
			KEY refresh_lineage (parent_id)
		) ENGINE=InnoDB {$collation};
		CREATE TABLE {$grant_table} (
			id bigint(20) unsigned NOT NULL AUTO_INCREMENT,
			issuer text NOT NULL,
			resource text NOT NULL,
			client_id text NOT NULL,
			client_digest char(64) NOT NULL,
			redirect_uri text NOT NULL,
			user_id bigint(20) unsigned NOT NULL,
			scope text NOT NULL,
			continuing_access tinyint(1) unsigned NOT NULL DEFAULT 0,
			status varchar(16) NOT NULL,
			authorized_at bigint(20) unsigned NOT NULL,
			last_used_at bigint(20) unsigned NOT NULL,
			refresh_absolute_expires_at bigint(20) unsigned NULL,
			refresh_inactivity_expires_at bigint(20) unsigned NULL,
			client_metadata_fingerprint char(64) NOT NULL DEFAULT '',
			revoked_at bigint(20) unsigned NULL,
			revocation_reason varchar(64) NULL,
			PRIMARY KEY  (id),
			KEY user_status (user_id,status),
			KEY client_status (client_digest,status)
		) ENGINE=InnoDB {$collation};
		CREATE TABLE {$client_table} (
			id bigint(20) unsigned NOT NULL AUTO_INCREMENT,
			issuer_digest char(64) NOT NULL,
			client_digest char(64) NOT NULL,
			issuer text NOT NULL,
			client_id text NOT NULL,
			client_name varchar(256) NOT NULL,
			redirect_uris longtext NOT NULL,
			status varchar(16) NOT NULL,
			source varchar(16) NOT NULL,
			token_endpoint_auth_method varchar(32) NOT NULL,
			grant_types varchar(128) NOT NULL,
			client_secret_hash varchar(255) NULL,
			metadata_fingerprint char(64) NOT NULL DEFAULT '',
			created_at bigint(20) unsigned NOT NULL,
			last_activity_at bigint(20) unsigned NOT NULL,
			authorized_at bigint(20) unsigned NULL,
			blocked_at bigint(20) unsigned NULL,
			deleted_at bigint(20) unsigned NULL,
			PRIMARY KEY  (id),
			UNIQUE KEY client_identity (client_digest),
			KEY issuer_registry (issuer_digest,status,source),
			KEY dynamic_lifecycle (issuer_digest,source,status,authorized_at,last_activity_at)
		) ENGINE=InnoDB {$collation};
		CREATE TABLE {$rate_table} (
			bucket_digest char(64) NOT NULL,
			window_started_at bigint(20) unsigned NOT NULL,
			window_seconds int(10) unsigned NOT NULL,
			request_count int(10) unsigned NOT NULL,
			expires_at bigint(20) unsigned NOT NULL,
			PRIMARY KEY  (bucket_digest),
			KEY expiry (expires_at)
		) ENGINE=InnoDB {$collation};
		CREATE TABLE {$audit_table} (
			id bigint(20) unsigned NOT NULL AUTO_INCREMENT,
			occurred_at bigint(20) unsigned NOT NULL,
			issuer_digest char(64) NOT NULL,
			issuer text NOT NULL,
			event_type varchar(64) NOT NULL,
			actor_user_id bigint(20) unsigned NULL,
			represented_user_id bigint(20) unsigned NULL,
			client_id text NULL,
			resource text NULL,
			scopes text NULL,
			outcome varchar(32) NOT NULL,
			reason varchar(64) NOT NULL,
			source_address varchar(64) NULL,
			PRIMARY KEY  (id),
			KEY issuer_events (issuer_digest,occurred_at),
			KEY retention (occurred_at)
		) ENGINE=InnoDB {$collation};
		CREATE TABLE {$cimd_table} (
			id bigint(20) unsigned NOT NULL AUTO_INCREMENT,
			issuer_digest char(64) NOT NULL,
			client_digest char(64) NOT NULL,
			issuer text NOT NULL,
			client_id text NOT NULL,
			client_name varchar(256) NOT NULL,
			redirect_uris longtext NOT NULL,
			grant_types varchar(128) NOT NULL,
			metadata_fingerprint char(64) NOT NULL,
			fetched_at bigint(20) unsigned NOT NULL,
			fresh_until bigint(20) unsigned NOT NULL,
			PRIMARY KEY  (id),
			UNIQUE KEY client_snapshot (client_digest),
			KEY issuer_freshness (issuer_digest,fresh_until)
		) ENGINE=InnoDB {$collation};";

		dbDelta( $sql );
		if ( ! self::isCurrent( $database, $table_name, $grant_table, $client_table, $rate_table, $audit_table, $cimd_table ) ) {
			throw new RuntimeException( 'charter_schema_installation_failed' );
		}
		update_option( self::VERSION_OPTION, self::VERSION, false );
	}

	/**
	 * Returns the current site's credential table name.
	 *
	 * @since 0.1.0
	 */
	public static function credentialTable(): string {
		return self::database()->prefix . 'charter_oauth_credentials';
	}

	/**
	 * Returns the current site's grant table name.
	 *
	 * @since 0.1.0
	 */
	public static function grantTable(): string {
		return self::database()->prefix . 'charter_oauth_grants';
	}

	/**
	 * Returns the current site's OAuth client table name.
	 *
	 * @since 0.1.0
	 */
	public static function clientTable(): string {
		return self::database()->prefix . 'charter_oauth_clients';
	}

	/**
	 * Returns the current site's OAuth rate-limit table name.
	 *
	 * @since 0.1.0
	 */
	public static function rateLimitTable(): string {
		return self::database()->prefix . 'charter_oauth_rate_limits';
	}

	/**
	 * Returns the current site's OAuth audit table name.
	 *
	 * @since 0.1.0
	 */
	public static function auditTable(): string {
		return self::database()->prefix . 'charter_oauth_audit';
	}

	/**
	 * Returns the current site's reusable Client ID Metadata Document table name.
	 */
	public static function clientMetadataTable(): string {
		return self::database()->prefix . 'charter_oauth_cimd_cache';
	}

	/**
	 * Returns the initialized WordPress database connection.
	 *
	 * @since 0.1.0
	 *
	 * @throws RuntimeException When WordPress database bootstrap is incomplete.
	 */
	private static function database(): \wpdb {
		global $wpdb;

		if ( ! $wpdb instanceof \wpdb ) {
			throw new RuntimeException( 'charter_database_unavailable' );
		}

		return $wpdb;
	}

	/**
	 * Confirms the credential table contains the fields needed by this version.
	 *
	 * @since 0.1.0
	 *
	 * @param \wpdb  $database  WordPress database connection.
	 * @param string $tableName Current site credential table.
	 * @param string $grantTableName Current site grant table.
	 * @param string $clientTableName Current site client table.
	 * @param string $rateTableName Current site rate-limit table.
	 * @param string $auditTableName Current site audit table.
	 * @param string $cimdTableName Current site CIMD snapshot table.
	 */
	private static function isCurrent( \wpdb $database, string $tableName, string $grantTableName, string $clientTableName, string $rateTableName, string $auditTableName, string $cimdTableName ): bool {
		$sql = $database->prepare( 'SHOW COLUMNS FROM %i', $tableName );
		if ( ! is_string( $sql ) ) {
			return false;
		}

		$columns         = $database->get_col( $sql ); // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching,WordPress.DB.PreparedSQL.NotPrepared -- Installation must verify the authoritative schema created above.
		$requiredColumns = array(
			'id',
			'credential_type',
			'digest',
			'issuer',
			'resource',
			'client_id',
			'redirect_uri',
			'user_id',
			'scope',
			'code_challenge',
			'request_state',
			'expires_at',
			'consumed_at',
			'created_at',
			'grant_id',
			'parent_id',
			'continuing_access',
			'client_metadata_fingerprint',
		);

		if ( array() !== array_diff( $requiredColumns, array_filter( $columns, 'is_string' ) ) ) {
			return false;
		}

		$indexSql = $database->prepare( 'SHOW INDEX FROM %i WHERE Key_name = %s', $tableName, 'credential' );
		if ( ! is_string( $indexSql ) ) {
			return false;
		}

		$indexRows = $database->get_results( $indexSql, ARRAY_A ); // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching,WordPress.DB.PreparedSQL.NotPrepared -- Installation must verify the authoritative uniqueness boundary created above.
		if ( ! is_array( $indexRows ) ) {
			return false;
		}
		$indexColumns = array();
		foreach ( $indexRows as $row ) {
			$nonUnique = $row['Non_unique'] ?? null;
			$column    = $row['Column_name'] ?? null;
			$sequence  = $row['Seq_in_index'] ?? null;
			if (
				'0' !== $nonUnique
				|| ! is_string( $column )
				|| ! is_string( $sequence )
				|| ! ctype_digit( $sequence )
			) {
				return false;
			}

			$indexColumns[ (int) $sequence ] = $column;
		}
		ksort( $indexColumns );

		if ( array( 'credential_type', 'digest' ) !== array_values( $indexColumns ) ) {
			return false;
		}

		$grantSql = $database->prepare( 'SHOW COLUMNS FROM %i', $grantTableName );
		if ( ! is_string( $grantSql ) ) {
			return false;
		}
		$grantColumns  = $database->get_col( $grantSql ); // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching,WordPress.DB.PreparedSQL.NotPrepared -- Installation must verify the authoritative grant schema created above.
		$requiredGrant = array(
			'id',
			'issuer',
			'resource',
			'client_id',
			'client_digest',
			'redirect_uri',
			'user_id',
			'scope',
			'continuing_access',
			'status',
			'authorized_at',
			'last_used_at',
			'refresh_absolute_expires_at',
			'refresh_inactivity_expires_at',
			'revoked_at',
			'revocation_reason',
			'client_metadata_fingerprint',
		);

		if ( array() !== array_diff( $requiredGrant, array_filter( $grantColumns, 'is_string' ) ) ) {
			return false;
		}

		$requiredTables = array(
			$clientTableName => array( 'id', 'issuer_digest', 'client_digest', 'issuer', 'client_id', 'client_name', 'redirect_uris', 'status', 'source', 'token_endpoint_auth_method', 'grant_types', 'client_secret_hash', 'metadata_fingerprint', 'created_at', 'last_activity_at', 'authorized_at', 'blocked_at', 'deleted_at' ),
			$rateTableName   => array( 'bucket_digest', 'window_started_at', 'window_seconds', 'request_count', 'expires_at' ),
			$auditTableName  => array( 'id', 'occurred_at', 'issuer_digest', 'issuer', 'event_type', 'actor_user_id', 'represented_user_id', 'client_id', 'resource', 'scopes', 'outcome', 'reason', 'source_address' ),
			$cimdTableName   => array( 'id', 'issuer_digest', 'client_digest', 'issuer', 'client_id', 'client_name', 'redirect_uris', 'grant_types', 'metadata_fingerprint', 'fetched_at', 'fresh_until' ),
		);
		foreach ( $requiredTables as $requiredTable => $requiredColumns ) {
			$tableSql = $database->prepare( 'SHOW COLUMNS FROM %i', $requiredTable );
			if ( ! is_string( $tableSql ) ) {
				return false;
			}
			$tableColumns = $database->get_col( $tableSql ); // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching,WordPress.DB.PreparedSQL.NotPrepared -- Installation verifies each authoritative table created above.
			if ( array() !== array_diff( $requiredColumns, array_filter( $tableColumns, 'is_string' ) ) ) {
				return false;
			}
		}

		return true;
	}

	/**
	 * This class contains static schema operations only.
	 */
	private function __construct() {
	}
}
