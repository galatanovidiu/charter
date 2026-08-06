<?php
/**
 * Reusable CIMD snapshot persistence.
 *
 * @package GalatanOvidiu\Charter
 */

declare(strict_types=1);

namespace GalatanOvidiu\Charter\OAuth;

use GalatanOvidiu\Charter\Schema;
use JsonException;
use mysqli;
use mysqli_result;
use RuntimeException;

/** Stores only currently reusable validated projections, never response bodies. */
final class ClientMetadataSnapshotStore {

	/**
	 * Owned transaction boundary.
	 *
	 * @var TransactionManager
	 */
	private readonly TransactionManager $transactions;

	/**
	 * Creates the reusable snapshot store.
	 *
	 * @param TransactionManager|null $transactions Optional owned transaction boundary.
	 */
	public function __construct( ?TransactionManager $transactions = null ) {
		$this->transactions = $transactions ?? new TransactionManager();
	}

	/**
	 * Returns a fresh exact snapshot or removes a stale non-authoritative projection.
	 *
	 * @param string $issuer Exact issuer.
	 * @param string $clientId Exact client identifier.
	 * @param int    $timestamp Current timestamp.
	 */
	public function findFresh( string $issuer, string $clientId, int $timestamp ): ?RemoteClientMetadata {
		return $this->transactions->run(
			function ( mysqli $database ) use ( $issuer, $clientId, $timestamp ): ?RemoteClientMetadata {
				$table  = self::quotedTable( Schema::clientMetadataTable() );
				$result = $database->execute_query(
					"SELECT issuer,client_id,client_name,redirect_uris,grant_types,metadata_fingerprint,fetched_at,fresh_until
					FROM {$table} WHERE client_digest = ? LIMIT 1 FOR UPDATE",
					array( self::clientDigest( $issuer, $clientId ) )
				); // phpcs:ignore WordPress.DB.RestrictedFunctions.mysql_mysqli -- Exact snapshot read and stale deletion use one owned transaction.
				if ( ! $result instanceof mysqli_result ) {
					throw new RuntimeException( 'charter_database_query_failed' );
				}
				$row = $result->fetch_assoc();
				$result->free();
				if ( ! is_array( $row ) || ! is_string( $row['issuer'] ?? null ) || ! is_string( $row['client_id'] ?? null ) || $row['issuer'] !== $issuer || $row['client_id'] !== $clientId ) {
					return null;
				}
				$freshUntil = self::integerValue( $row['fresh_until'] ?? null );
				if ( null === $freshUntil || $timestamp >= $freshUntil ) {
					$database->execute_query( "DELETE FROM {$table} WHERE client_digest = ?", array( self::clientDigest( $issuer, $clientId ) ) ); // phpcs:ignore WordPress.DB.RestrictedFunctions.mysql_mysqli -- Stale remote metadata must not remain authoritative.
					return null;
				}

				return self::metadataFromRow( $row );
			}
		);
	}

	/**
	 * Stores one validated projection until its exclusive freshness boundary.
	 *
	 * @param string               $issuer Exact issuer.
	 * @param RemoteClientMetadata $metadata Validated remote projection.
	 * @param int                  $fetchedAt Response wall time.
	 * @param int                  $freshUntil Exclusive freshness boundary.
	 * @throws RuntimeException When persistence fails.
	 */
	public function store( string $issuer, RemoteClientMetadata $metadata, int $fetchedAt, int $freshUntil ): void {
		if ( $freshUntil <= $fetchedAt ) {
			$this->delete( $issuer, $metadata->clientId() );
			return;
		}
		$redirects = wp_json_encode( $metadata->redirectUris(), JSON_UNESCAPED_SLASHES );
		if ( ! is_string( $redirects ) ) {
			throw new RuntimeException( 'charter_cimd_snapshot_invalid' );
		}

		$this->transactions->run(
			static function ( mysqli $database ) use ( $issuer, $metadata, $fetchedAt, $freshUntil, $redirects ): void {
				$table  = self::quotedTable( Schema::clientMetadataTable() );
				$result = $database->execute_query(
					"INSERT INTO {$table}
					(issuer_digest,client_digest,issuer,client_id,client_name,redirect_uris,grant_types,metadata_fingerprint,fetched_at,fresh_until)
					VALUES (?,?,?,?,?,?,?,?,?,?)
					ON DUPLICATE KEY UPDATE issuer = VALUES(issuer), client_id = VALUES(client_id), client_name = VALUES(client_name), redirect_uris = VALUES(redirect_uris), grant_types = VALUES(grant_types), metadata_fingerprint = VALUES(metadata_fingerprint), fetched_at = VALUES(fetched_at), fresh_until = VALUES(fresh_until)",
					array(
						self::issuerDigest( $issuer ),
						self::clientDigest( $issuer, $metadata->clientId() ),
						$issuer,
						$metadata->clientId(),
						$metadata->name(),
						$redirects,
						implode( ' ', $metadata->grantTypes() ),
						$metadata->fingerprint(),
						$fetchedAt,
						$freshUntil,
					)
				); // phpcs:ignore WordPress.DB.RestrictedFunctions.mysql_mysqli -- Authoritative bounded snapshot replacement uses an owned connection.
				if ( true !== $result ) {
					throw new RuntimeException( 'charter_cimd_snapshot_failed' );
				}
			}
		);
	}

	/**
	 * Removes any reusable projection for one exact client.
	 *
	 * @param string $issuer Exact issuer.
	 * @param string $clientId Exact client identifier.
	 */
	public function delete( string $issuer, string $clientId ): void {
		$this->transactions->run(
			static function ( mysqli $database ) use ( $issuer, $clientId ): void {
				$table = self::quotedTable( Schema::clientMetadataTable() );
				if ( true !== $database->execute_query( "DELETE FROM {$table} WHERE client_digest = ? AND issuer = ? AND client_id = ?", array( self::clientDigest( $issuer, $clientId ), $issuer, $clientId ) ) ) { // phpcs:ignore WordPress.DB.RestrictedFunctions.mysql_mysqli -- Exact cache invalidation uses an owned connection.
					throw new RuntimeException( 'charter_cimd_snapshot_failed' );
				}
			}
		);
	}

	/** Deletes current-site snapshots during tests or uninstall. */
	public function deleteAll(): void {
		$this->transactions->run(
			static function ( mysqli $database ): void {
				$table = self::quotedTable( Schema::clientMetadataTable() );
				if ( true !== $database->query( "DELETE FROM {$table}" ) ) { // phpcs:ignore WordPress.DB.RestrictedFunctions.mysql_mysqli -- Bounded owned cleanup.
					throw new RuntimeException( 'charter_cimd_snapshot_failed' );
				}
			}
		);
	}

	/**
	 * Reconstructs one validated projection from storage.
	 *
	 * @param array<mixed> $row Database row.
	 */
	private static function metadataFromRow( array $row ): ?RemoteClientMetadata {
		foreach ( array( 'client_id', 'client_name', 'redirect_uris', 'grant_types', 'metadata_fingerprint' ) as $field ) {
			if ( ! is_string( $row[ $field ] ?? null ) ) {
				return null;
			}
		}
		try {
			$redirects = json_decode( $row['redirect_uris'], true, 8, JSON_THROW_ON_ERROR );
		} catch ( JsonException ) {
			return null;
		}
		if ( ! is_array( $redirects ) || ! array_is_list( $redirects ) || 1 !== preg_match( '/^[0-9a-f]{64}$/D', $row['metadata_fingerprint'] ) ) {
			return null;
		}
		$validatedRedirects = array();
		foreach ( $redirects as $redirect ) {
			if ( ! is_string( $redirect ) || ! RedirectUriValidator::isValid( $redirect ) ) {
				return null;
			}
			$validatedRedirects[] = $redirect;
		}
		$grants = '' === $row['grant_types'] ? array() : explode( ' ', $row['grant_types'] );
		if ( ! in_array( Client::GRANT_AUTHORIZATION_CODE, $grants, true ) || array() !== array_diff( $grants, array( Client::GRANT_AUTHORIZATION_CODE, Client::GRANT_REFRESH_TOKEN ) ) ) {
			return null;
		}

		return new RemoteClientMetadata( $row['client_id'], $row['client_name'], $validatedRedirects, $grants, $row['metadata_fingerprint'] );
	}

	/**
	 * Parses one non-negative stored integer.
	 *
	 * @param mixed $value Stored value.
	 */
	private static function integerValue( mixed $value ): ?int {
		return is_int( $value ) && 0 <= $value ? $value : ( is_string( $value ) && ctype_digit( $value ) ? (int) $value : null );
	}

	/**
	 * Returns the issuer lookup digest.
	 *
	 * @param string $issuer Exact issuer.
	 */
	private static function issuerDigest( string $issuer ): string {
		return hash( 'sha256', 'issuer:' . strlen( $issuer ) . ':' . $issuer );
	}

	/**
	 * Returns the exact issuer/client lookup digest.
	 *
	 * @param string $issuer Exact issuer.
	 * @param string $clientId Exact client identifier.
	 */
	private static function clientDigest( string $issuer, string $clientId ): string {
		return hash( 'sha256', strlen( $issuer ) . ':' . $issuer . strlen( $clientId ) . ':' . $clientId );
	}

	/**
	 * Returns a validated quoted table identifier.
	 *
	 * @param string $table Candidate table identifier.
	 * @throws RuntimeException When the identifier is invalid.
	 */
	private static function quotedTable( string $table ): string {
		if ( 1 !== preg_match( '/^[A-Za-z0-9_]+$/D', $table ) ) {
			throw new RuntimeException( 'charter_database_table_invalid' );
		}

		return '`' . $table . '`';
	}
}
