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
	private const VERSION        = '2';

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

		$database    = self::database();
		$table_name  = self::credentialTable();
		$collation   = $database->get_charset_collate();
		$grant_table = self::grantTable();
		$sql         = "CREATE TABLE {$table_name} (
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
			revoked_at bigint(20) unsigned NULL,
			revocation_reason varchar(64) NULL,
			PRIMARY KEY  (id),
			KEY user_status (user_id,status),
			KEY client_status (client_digest,status)
		) ENGINE=InnoDB {$collation};";

		dbDelta( $sql );
		if ( ! self::isCurrent( $database, $table_name, $grant_table ) ) {
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
	 */
	private static function isCurrent( \wpdb $database, string $tableName, string $grantTableName ): bool {
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
		);

		return array() === array_diff( $requiredGrant, array_filter( $grantColumns, 'is_string' ) );
	}

	/**
	 * This class contains static schema operations only.
	 */
	private function __construct() {
	}
}
