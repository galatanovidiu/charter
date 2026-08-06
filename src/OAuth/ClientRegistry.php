<?php
/**
 * Issuer-scoped OAuth client persistence.
 *
 * @package GalatanOvidiu\Charter
 */

declare(strict_types=1);

namespace GalatanOvidiu\Charter\OAuth;

use GalatanOvidiu\Charter\Schema;
use InvalidArgumentException;
use JsonException;
use mysqli;
use mysqli_result;
use RuntimeException;

/**
 * Stores immutable client security identities and their governance lifecycle.
 *
 * @since 0.1.0
 *
 * @phpstan-type ClientIdentityRecord array{issuer:string,client_id:string,client_name:string,redirect_uris:list<string>,status:string,token_endpoint_auth_method:string,grant_types:list<string>,client_secret_hash:?string,metadata_fingerprint:string}
 * @phpstan-type StoredClientRecord array{issuer:string,client_id:string,client_name:string,redirect_uris:list<string>,status:string,source:string,token_endpoint_auth_method:string,grant_types:list<string>,client_secret_hash:?string,metadata_fingerprint:string,created_at:int,last_activity_at:int,authorized_at:?int}
 */
final class ClientRegistry {

	public const SOURCE_PRE_REGISTERED = 'pre_registered';
	public const SOURCE_DYNAMIC        = 'dynamic';
	public const SOURCE_CIMD           = 'cimd';

	public const STATUS_ACTIVE  = 'active';
	public const STATUS_BLOCKED = 'blocked';
	public const STATUS_DELETED = 'deleted';

	private const LEGACY_OPTION          = 'charter_oauth_clients';
	private const LEGACY_MIGRATED_OPTION = 'charter_oauth_clients_migrated';
	private const MAX_NEVER_AUTHORIZED   = 500;

	/**
	 * Owned non-reconnecting transaction service.
	 *
	 * @var TransactionManager
	 */
	private readonly TransactionManager $transactions;

	/**
	 * Creates the registry.
	 *
	 * @param TransactionManager|null $transactions Owned transaction service.
	 */
	public function __construct( ?TransactionManager $transactions = null ) {
		$this->transactions = $transactions ?? new TransactionManager();
	}

	/**
	 * Registers one operator-managed public client without a secret.
	 *
	 * @param string        $issuer Exact issuer.
	 * @param string        $clientId Exact client identifier.
	 * @param string        $name User-facing name.
	 * @param array<string> $redirectUris Exact redirects.
	 * @param bool          $supportsRefresh Whether refresh is declared.
	 * @throws InvalidArgumentException When input is invalid or changes an identity.
	 */
	public function registerPublicClient( string $issuer, string $clientId, string $name, array $redirectUris, bool $supportsRefresh = false ): bool {
		$this->migrateLegacyRecords();
		$record = $this->registrationRecord( $issuer, $clientId, $name, $redirectUris, Client::AUTH_NONE, $supportsRefresh, null );

		return $this->insertFixedRegistration( $record, true );
	}

	/**
	 * Registers one operator-managed confidential client and reveals its secret once.
	 *
	 * @param string        $issuer Exact issuer.
	 * @param string        $clientId Exact client identifier.
	 * @param string        $name User-facing name.
	 * @param array<string> $redirectUris Exact redirects.
	 * @param bool          $supportsRefresh Whether refresh is declared.
	 * @throws RuntimeException When secure persistence fails.
	 */
	public function registerConfidentialClient( string $issuer, string $clientId, string $name, array $redirectUris, bool $supportsRefresh = true ): string {
		$this->migrateLegacyRecords();
		$secret = 'chs_' . self::base64UrlEncode( random_bytes( 32 ) );
		$hash   = password_hash( $secret, PASSWORD_DEFAULT );

		$record = $this->registrationRecord( $issuer, $clientId, $name, $redirectUris, Client::AUTH_CLIENT_SECRET_POST, $supportsRefresh, $hash );
		if ( ! $this->insertFixedRegistration( $record, false ) ) {
			throw new RuntimeException( 'charter_client_registration_failed' );
		}

		return $secret;
	}

	/**
	 * Atomically creates one quota-bound immutable dynamic registration.
	 *
	 * @param string        $issuer Exact issuer.
	 * @param string        $name User-facing name.
	 * @param array<string> $redirectUris Exact redirects.
	 * @param string        $authenticationMethod Required method.
	 * @param bool          $supportsRefresh Whether refresh is declared.
	 * @param int           $timestamp Current timestamp.
	 * @return array{client:Client,client_secret:string|null} New registration.
	 * @throws RuntimeException When persistence fails.
	 */
	public function registerDynamicClient( string $issuer, string $name, array $redirectUris, string $authenticationMethod, bool $supportsRefresh, int $timestamp ): array {
		$this->migrateLegacyRecords();
		$clientId   = 'chd_' . self::base64UrlEncode( random_bytes( 32 ) );
		$secret     = null;
		$secretHash = null;
		if ( Client::AUTH_CLIENT_SECRET_POST === $authenticationMethod ) {
			$secret     = 'chs_' . self::base64UrlEncode( random_bytes( 32 ) );
			$secretHash = password_hash( $secret, PASSWORD_DEFAULT );
		}

		$record       = $this->registrationRecord( $issuer, $clientId, $name, $redirectUris, $authenticationMethod, $supportsRefresh, $secretHash );
		$issuerDigest = self::issuerDigest( $issuer );
		$this->transactions->run(
			function ( mysqli $database ) use ( $record, $issuerDigest, $timestamp ): void {
				$table  = self::quotedTable( Schema::clientTable() );
				$result = $database->execute_query(
					"SELECT id FROM {$table}
					WHERE issuer_digest = ? AND source = ? AND status = ? AND authorized_at IS NULL
					FOR UPDATE",
					array( $issuerDigest, self::SOURCE_DYNAMIC, self::STATUS_ACTIVE )
				); // phpcs:ignore WordPress.DB.RestrictedFunctions.mysql_mysqli -- Quota enforcement uses an owned non-reconnecting transaction and index range lock.
				if ( ! $result instanceof mysqli_result ) {
					throw new RuntimeException( 'charter_database_query_failed' );
				}
				$count = $result->num_rows;
				$result->free();
				if ( self::MAX_NEVER_AUTHORIZED <= $count ) {
					throw new DynamicRegistrationQuotaException( 'charter_dcr_never_authorized_quota' );
				}

				$this->insertRecord( $database, $record, self::SOURCE_DYNAMIC, $timestamp );
			}
		);

		$client = $this->findActive( $issuer, $clientId );
		if ( null === $client ) {
			throw new RuntimeException( 'charter_client_registration_failed' );
		}

		return array(
			'client'        => $client,
			'client_secret' => $secret,
		);
	}

	/**
	 * Finds one exact active registration.
	 *
	 * @param string $issuer Exact issuer.
	 * @param string $clientId Exact client identifier.
	 */
	public function findActive( string $issuer, string $clientId ): ?Client {
		$this->migrateLegacyRecords();
		$record = $this->findRecord( $issuer, $clientId );
		if ( null === $record || self::STATUS_ACTIVE !== $record['status'] ) {
			return null;
		}

		return self::clientFromRecord( $record );
	}

	/**
	 * Authenticates one active client for token-like endpoints.
	 *
	 * @param string      $issuer Exact issuer.
	 * @param string      $clientId Presented identifier.
	 * @param bool        $secretPresented Whether a secret parameter was present.
	 * @param string|null $clientSecret Presented secret.
	 */
	public function authenticateForTokenEndpoint( string $issuer, string $clientId, bool $secretPresented, ?string $clientSecret ): ?Client {
		$client = $this->findActive( $issuer, $clientId );
		if ( null === $client ) {
			if ( $secretPresented && is_string( $clientSecret ) && '' !== $clientSecret ) {
				password_verify( $clientSecret, '$2y$10$usesomesillystringfore7hnbRJHxXVLeakoG8K30oukPsA.ztMG' );
			}
			return null;
		}

		if ( Client::AUTH_NONE === $client->authenticationMethod() ) {
			return $secretPresented ? null : $client;
		}
		if ( ! $secretPresented || ! is_string( $clientSecret ) || 256 < strlen( $clientSecret ) ) {
			return null;
		}

		return $client->authenticatesClientSecret( $clientSecret ) ? $client : null;
	}

	/**
	 * Lists all current and terminal registrations for one issuer.
	 *
	 * @param string $issuer Exact issuer.
	 * @return array<ClientRegistrationRecord> Most recent first.
	 */
	public function listForIssuer( string $issuer ): array {
		$this->migrateLegacyRecords();
		return $this->transactions->run(
			function ( mysqli $database ) use ( $issuer ): array {
				$table  = self::quotedTable( Schema::clientTable() );
				$result = $database->execute_query(
					"SELECT issuer,client_id,client_name,redirect_uris,status,source,token_endpoint_auth_method,grant_types,metadata_fingerprint,created_at,last_activity_at,authorized_at,client_secret_hash
					FROM {$table} WHERE issuer_digest = ? ORDER BY created_at DESC, id DESC LIMIT 1000",
					array( self::issuerDigest( $issuer ) )
				); // phpcs:ignore WordPress.DB.RestrictedFunctions.mysql_mysqli -- Administrator registry reads use an owned connection.
				if ( ! $result instanceof mysqli_result ) {
					throw new RuntimeException( 'charter_database_query_failed' );
				}

				$records = array();
				while ( true ) {
					$row = $result->fetch_assoc();
					if ( ! is_array( $row ) ) {
						break;
					}
					$record = self::recordFromRow( $row );
					if ( null !== $record && $record['issuer'] === $issuer ) {
						$records[] = self::registrationProjection( $record );
					}
				}
				$result->free();

				return $records;
			}
		);
	}

	/**
	 * Blocks an active client immediately.
	 *
	 * @param string $issuer Exact issuer.
	 * @param string $clientId Exact client identifier.
	 * @param int    $timestamp Current timestamp.
	 */
	public function block( string $issuer, string $clientId, int $timestamp ): bool {
		return $this->transitionStatus( $issuer, $clientId, self::STATUS_ACTIVE, self::STATUS_BLOCKED, $timestamp );
	}

	/**
	 * Tombstones an active or blocked registration and erases secret metadata.
	 *
	 * @param string $issuer Exact issuer.
	 * @param string $clientId Exact client identifier.
	 * @param int    $timestamp Current timestamp.
	 */
	public function delete( string $issuer, string $clientId, int $timestamp ): bool {
		$this->migrateLegacyRecords();
		return $this->transactions->run(
			function ( mysqli $database ) use ( $issuer, $clientId, $timestamp ): bool {
				$table  = self::quotedTable( Schema::clientTable() );
				$result = $database->execute_query(
					"UPDATE {$table}
					SET status = ?, client_name = ?, redirect_uris = ?, grant_types = ?, client_secret_hash = NULL, metadata_fingerprint = '', deleted_at = ?
					WHERE client_digest = ? AND issuer = ? AND client_id = ? AND status IN (?,?)",
					array(
						self::STATUS_DELETED,
						'[deleted]',
						'[]',
						Client::GRANT_AUTHORIZATION_CODE,
						$timestamp,
						self::clientDigest( $issuer, $clientId ),
						$issuer,
						$clientId,
						self::STATUS_ACTIVE,
						self::STATUS_BLOCKED,
					)
				); // phpcs:ignore WordPress.DB.RestrictedFunctions.mysql_mysqli -- Governance transition uses an owned transaction.

				if ( true !== $result ) {
					return false;
				}

				$record = $this->selectRecord( $database, $issuer, $clientId, false );
				return null !== $record && self::STATUS_DELETED === $record['status'];
			}
		);
	}

	/**
	 * Records successful authorization so DCR quotas and cleanup remain correct.
	 *
	 * @param string $issuer Exact issuer.
	 * @param string $clientId Exact client identifier.
	 * @param int    $timestamp Current timestamp.
	 */
	public function markAuthorized( string $issuer, string $clientId, int $timestamp ): bool {
		$this->migrateLegacyRecords();
		return $this->transactions->run(
			function ( mysqli $database ) use ( $issuer, $clientId, $timestamp ): bool {
				$table  = self::quotedTable( Schema::clientTable() );
				$result = $database->execute_query(
					"UPDATE {$table} SET authorized_at = COALESCE(authorized_at, ?), last_activity_at = ?
					WHERE client_digest = ? AND issuer = ? AND client_id = ? AND status = ?",
					array( $timestamp, $timestamp, self::clientDigest( $issuer, $clientId ), $issuer, $clientId, self::STATUS_ACTIVE )
				); // phpcs:ignore WordPress.DB.RestrictedFunctions.mysql_mysqli -- Lifecycle activity uses an owned connection.

				if ( true !== $result ) {
					return false;
				}

				$record = $this->selectRecord( $database, $issuer, $clientId, false );
				return null !== $record && self::STATUS_ACTIVE === $record['status'] && null !== $record['authorized_at'];
			}
		);
	}

	/**
	 * Records successful token lifecycle activity without making issuance depend on telemetry.
	 *
	 * @param string $issuer Exact issuer.
	 * @param string $clientId Exact client identifier.
	 * @param int    $timestamp Current timestamp.
	 */
	public function markActivity( string $issuer, string $clientId, int $timestamp ): bool {
		try {
			$this->migrateLegacyRecords();
			return $this->transactions->run(
				function ( mysqli $database ) use ( $issuer, $clientId, $timestamp ): bool {
					$table  = self::quotedTable( Schema::clientTable() );
					$result = $database->execute_query(
						"UPDATE {$table} SET last_activity_at = ?
						WHERE client_digest = ? AND issuer = ? AND client_id = ? AND status = ?",
						array( $timestamp, self::clientDigest( $issuer, $clientId ), $issuer, $clientId, self::STATUS_ACTIVE )
					); // phpcs:ignore WordPress.DB.RestrictedFunctions.mysql_mysqli -- Best-effort lifecycle activity uses an owned connection.

					return true === $result && 1 === $database->affected_rows;
				}
			);
		} catch ( RuntimeException ) {
			return false;
		}
	}

	/**
	 * Deletes all current-site registrations during tests or uninstall.
	 */
	public function deleteAll(): void {
		$this->transactions->run(
			static function ( mysqli $database ): void {
				$table = self::quotedTable( Schema::clientTable() );
				if ( true !== $database->query( "DELETE FROM {$table}" ) ) { // phpcs:ignore WordPress.DB.RestrictedFunctions.mysql_mysqli -- Bounded owned cleanup.
					throw new RuntimeException( 'charter_client_cleanup_failed' );
				}
			}
		);
		delete_option( self::LEGACY_OPTION );
		delete_option( self::LEGACY_MIGRATED_OPTION );
	}

	/**
	 * Finds dynamic clients eligible for bounded abandoned-registration cleanup.
	 *
	 * @param string $issuer Exact issuer.
	 * @param int    $timestamp Current timestamp.
	 * @param int    $limit Maximum records.
	 * @return array<ClientRegistrationRecord>
	 */
	public function findAbandonedDynamicClients( string $issuer, int $timestamp, int $limit = 100 ): array {
		$this->migrateLegacyRecords();
		$limit = max( 1, min( 100, $limit ) );
		return array_slice(
			array_values(
				array_filter(
					$this->listForIssuer( $issuer ),
					static function ( ClientRegistrationRecord $record ) use ( $timestamp ): bool {
						if ( self::SOURCE_DYNAMIC !== $record->source() || self::STATUS_ACTIVE !== $record->status() ) {
							return false;
						}
						$eligibleAt = null === $record->authorizedAt()
							? $record->createdAt() + 7 * DAY_IN_SECONDS
							: $record->lastActivityAt() + 90 * DAY_IN_SECONDS;

						return $eligibleAt <= $timestamp;
					}
				)
			),
			0,
			$limit
		);
	}

	/**
	 * Inserts or confirms one immutable pre-registration.
	 *
	 * @param array<string,mixed> $record Validated record.
	 * @param bool                $idempotent Whether an identical existing record succeeds.
	 * @phpstan-param ClientIdentityRecord $record
	 */
	private function insertFixedRegistration( array $record, bool $idempotent ): bool {
		return $this->transactions->run(
			function ( mysqli $database ) use ( $record, $idempotent ): bool {
				$existing = $this->selectRecord( $database, $record['issuer'], $record['client_id'], true );
				if ( null !== $existing ) {
					if ( $idempotent && self::sameSecurityIdentity( $existing, $record ) && self::STATUS_ACTIVE === $existing['status'] ) {
						return true;
					}
					throw new InvalidArgumentException( 'charter_client_identity_change_requires_new_id' );
				}

				$this->insertRecord( $database, $record, self::SOURCE_PRE_REGISTERED, time() );
				return true;
			}
		);
	}

	/**
	 * Builds one validated immutable registration record.
	 *
	 * @param string        $issuer Exact issuer.
	 * @param string        $clientId Exact identifier.
	 * @param string        $name Display name.
	 * @param array<string> $redirectUris Exact redirects.
	 * @param string        $authenticationMethod Token method.
	 * @param bool          $supportsRefresh Whether refresh is declared.
	 * @param string|null   $clientSecretHash One-way secret hash.
	 * @return array<string,mixed>
	 * @phpstan-return ClientIdentityRecord
	 * @throws InvalidArgumentException When the security identity is invalid.
	 */
	private function registrationRecord( string $issuer, string $clientId, string $name, array $redirectUris, string $authenticationMethod, bool $supportsRefresh, ?string $clientSecretHash ): array {
		$name = trim( $name );
		if ( '' === $issuer || '' === $clientId || 2048 < strlen( $clientId ) || '' === $name || 256 < strlen( $name ) || array() === $redirectUris || 32 < count( $redirectUris ) ) {
			throw new InvalidArgumentException( 'charter_client_registration_invalid' );
		}

		$redirectUris = array_values( array_unique( $redirectUris ) );
		foreach ( $redirectUris as $redirectUri ) {
			if ( ! RedirectUriValidator::isValid( $redirectUri ) ) {
				throw new InvalidArgumentException( 'charter_client_redirect_invalid' );
			}
		}

		if (
			! in_array( $authenticationMethod, array( Client::AUTH_NONE, Client::AUTH_CLIENT_SECRET_POST ), true )
			|| ( Client::AUTH_NONE === $authenticationMethod && null !== $clientSecretHash )
			|| ( Client::AUTH_CLIENT_SECRET_POST === $authenticationMethod && ! is_string( $clientSecretHash ) )
		) {
			throw new InvalidArgumentException( 'charter_client_registration_invalid' );
		}

		$grantTypes = array( Client::GRANT_AUTHORIZATION_CODE );
		if ( $supportsRefresh ) {
			$grantTypes[] = Client::GRANT_REFRESH_TOKEN;
		}

		return array(
			'issuer'                     => $issuer,
			'client_id'                  => $clientId,
			'client_name'                => $name,
			'redirect_uris'              => $redirectUris,
			'status'                     => self::STATUS_ACTIVE,
			'token_endpoint_auth_method' => $authenticationMethod,
			'grant_types'                => $grantTypes,
			'client_secret_hash'         => $clientSecretHash,
			'metadata_fingerprint'       => hash( 'sha256', self::securityIdentityJson( $name, $redirectUris, $authenticationMethod, $grantTypes ) ),
		);
	}

	/**
	 * Inserts one already validated row.
	 *
	 * @param mysqli              $database Owned connection.
	 * @param array<string,mixed> $record Validated record.
	 * @param string              $source Onboarding source.
	 * @param int                 $timestamp Creation timestamp.
	 * @phpstan-param ClientIdentityRecord $record
	 * @throws RuntimeException When persistence fails.
	 */
	private function insertRecord( mysqli $database, array $record, string $source, int $timestamp ): void {
		$table     = self::quotedTable( Schema::clientTable() );
		$redirects = self::jsonEncode( $record['redirect_uris'] );
		$grants    = implode( ' ', $record['grant_types'] );
		$result    = $database->execute_query(
			"INSERT INTO {$table}
			(issuer_digest,client_digest,issuer,client_id,client_name,redirect_uris,status,source,token_endpoint_auth_method,grant_types,client_secret_hash,metadata_fingerprint,created_at,last_activity_at,authorized_at,blocked_at,deleted_at)
			VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,NULL,NULL,NULL)",
			array(
				self::issuerDigest( $record['issuer'] ),
				self::clientDigest( $record['issuer'], $record['client_id'] ),
				$record['issuer'],
				$record['client_id'],
				$record['client_name'],
				$redirects,
				self::STATUS_ACTIVE,
				$source,
				$record['token_endpoint_auth_method'],
				$grants,
				$record['client_secret_hash'],
				$record['metadata_fingerprint'],
				$timestamp,
				$timestamp,
			)
		); // phpcs:ignore WordPress.DB.RestrictedFunctions.mysql_mysqli -- Authoritative client insertion uses an owned transaction.
		if ( true !== $result || 1 !== $database->affected_rows ) {
			throw new RuntimeException( 'charter_client_registration_failed' );
		}
	}

	/**
	 * Loads one exact registration.
	 *
	 * @param string $issuer Exact issuer.
	 * @param string $clientId Exact client identifier.
	 * @return array<string,mixed>|null
	 * @phpstan-return StoredClientRecord|null
	 */
	private function findRecord( string $issuer, string $clientId ): ?array {
		return $this->transactions->run(
			fn ( mysqli $database ): ?array => $this->selectRecord( $database, $issuer, $clientId, false )
		);
	}

	/**
	 * Selects and optionally locks one exact registration.
	 *
	 * @param mysqli $database Owned connection.
	 * @param string $issuer Exact issuer.
	 * @param string $clientId Exact client identifier.
	 * @param bool   $lock Whether to lock the row.
	 * @return array<string,mixed>|null
	 * @phpstan-return StoredClientRecord|null
	 * @throws RuntimeException When the query fails.
	 */
	private function selectRecord( mysqli $database, string $issuer, string $clientId, bool $lock ): ?array {
		$table  = self::quotedTable( Schema::clientTable() );
		$suffix = $lock ? ' FOR UPDATE' : '';
		$result = $database->execute_query(
			"SELECT issuer,client_id,client_name,redirect_uris,status,source,token_endpoint_auth_method,grant_types,client_secret_hash,metadata_fingerprint,created_at,last_activity_at,authorized_at
			FROM {$table} WHERE client_digest = ? LIMIT 1{$suffix}",
			array( self::clientDigest( $issuer, $clientId ) )
		); // phpcs:ignore WordPress.DB.RestrictedFunctions.mysql_mysqli -- Authoritative exact lookup uses an owned connection.
		if ( ! $result instanceof mysqli_result ) {
			throw new RuntimeException( 'charter_database_query_failed' );
		}
		$row = $result->fetch_assoc();
		$result->free();
		$record = is_array( $row ) ? self::recordFromRow( $row ) : null;

		return null !== $record && $record['issuer'] === $issuer && $record['client_id'] === $clientId ? $record : null;
	}

	/**
	 * Transitions one exact status.
	 *
	 * @param string $issuer Exact issuer.
	 * @param string $clientId Exact client identifier.
	 * @param string $from Required current status.
	 * @param string $to Target status.
	 * @param int    $timestamp Current timestamp.
	 */
	private function transitionStatus( string $issuer, string $clientId, string $from, string $to, int $timestamp ): bool {
		$this->migrateLegacyRecords();
		return $this->transactions->run(
			function ( mysqli $database ) use ( $issuer, $clientId, $from, $to, $timestamp ): bool {
				$table  = self::quotedTable( Schema::clientTable() );
				$result = $database->execute_query(
					"UPDATE {$table} SET status = ?, blocked_at = ? WHERE client_digest = ? AND issuer = ? AND client_id = ? AND status = ?",
					array( $to, $timestamp, self::clientDigest( $issuer, $clientId ), $issuer, $clientId, $from )
				); // phpcs:ignore WordPress.DB.RestrictedFunctions.mysql_mysqli -- Governance transition uses an owned connection.

				return true === $result && 1 === $database->affected_rows;
			}
		);
	}

	/**
	 * Migrates the option-backed initial implementation exactly once.
	 */
	private function migrateLegacyRecords(): void {
		if ( true === get_option( self::LEGACY_MIGRATED_OPTION, false ) ) {
			return;
		}

		$legacy = get_option( self::LEGACY_OPTION, array() );
		if ( is_array( $legacy ) ) {
			foreach ( $legacy as $candidate ) {
				if ( ! is_array( $candidate ) ) {
					continue;
				}
				$normalized = $this->legacyRecord( $candidate );
				if ( null === $normalized ) {
					continue;
				}
				$this->transactions->run(
					function ( mysqli $database ) use ( $normalized ): void {
						if ( null === $this->selectRecord( $database, $normalized['issuer'], $normalized['client_id'], true ) ) {
							$this->insertRecord( $database, $normalized, self::SOURCE_PRE_REGISTERED, time() );
						}
					}
				);
			}
		}

		update_option( self::LEGACY_MIGRATED_OPTION, true, false );
		delete_option( self::LEGACY_OPTION );
	}

	/**
	 * Validates one legacy option record for migration.
	 *
	 * @param array<mixed> $record Stored legacy record.
	 * @return array<string,mixed>|null
	 * @phpstan-return ClientIdentityRecord|null
	 */
	private function legacyRecord( array $record ): ?array {
		$issuer       = $record['issuer'] ?? null;
		$clientId     = $record['client_id'] ?? null;
		$name         = $record['name'] ?? null;
		$redirectUris = $record['redirect_uris'] ?? null;
		$method       = $record['token_endpoint_auth_method'] ?? Client::AUTH_NONE;
		$grantTypes   = $record['grant_types'] ?? array( Client::GRANT_AUTHORIZATION_CODE );
		$secretHash   = $record['client_secret_hash'] ?? null;
		if ( ! is_string( $issuer ) || ! is_string( $clientId ) || ! is_string( $name ) || ! is_array( $redirectUris ) || ! is_string( $method ) || ! is_array( $grantTypes ) || ( null !== $secretHash && ! is_string( $secretHash ) ) ) {
			return null;
		}

		try {
			return $this->registrationRecord(
				$issuer,
				$clientId,
				$name,
				array_values( array_filter( $redirectUris, 'is_string' ) ),
				$method,
				in_array( Client::GRANT_REFRESH_TOKEN, $grantTypes, true ),
				$secretHash
			);
		} catch ( InvalidArgumentException ) {
			return null;
		}
	}

	/**
	 * Converts one database row into a validated record.
	 *
	 * @param array<mixed> $row Database row.
	 * @return array<string,mixed>|null
	 * @phpstan-return StoredClientRecord|null
	 */
	private static function recordFromRow( array $row ): ?array {
		foreach ( array( 'issuer', 'client_id', 'client_name', 'redirect_uris', 'status', 'source', 'token_endpoint_auth_method', 'grant_types', 'metadata_fingerprint' ) as $field ) {
			if ( ! is_string( $row[ $field ] ?? null ) ) {
				return null;
			}
		}

		try {
			$redirectUris = json_decode( $row['redirect_uris'], true, 8, JSON_THROW_ON_ERROR );
		} catch ( JsonException ) {
			return null;
		}
		$grantTypes   = '' === $row['grant_types'] ? array() : explode( ' ', $row['grant_types'] );
		$createdAt    = self::integerValue( $row['created_at'] ?? null );
		$lastActivity = self::integerValue( $row['last_activity_at'] ?? null );
		$authorizedAt = self::nullableIntegerValue( $row['authorized_at'] ?? null );
		$secretHash   = $row['client_secret_hash'] ?? null;
		if ( ! is_array( $redirectUris ) || ! array_is_list( $redirectUris ) || null === $createdAt || null === $lastActivity || ( null !== $secretHash && ! is_string( $secretHash ) ) ) {
			return null;
		}
		$validatedRedirects = array();
		foreach ( $redirectUris as $redirectUri ) {
			if ( ! is_string( $redirectUri ) ) {
				return null;
			}
			$validatedRedirects[] = $redirectUri;
		}

		return array(
			'issuer'                     => $row['issuer'],
			'client_id'                  => $row['client_id'],
			'client_name'                => $row['client_name'],
			'redirect_uris'              => $validatedRedirects,
			'status'                     => $row['status'],
			'source'                     => $row['source'],
			'token_endpoint_auth_method' => $row['token_endpoint_auth_method'],
			'grant_types'                => $grantTypes,
			'client_secret_hash'         => $secretHash,
			'metadata_fingerprint'       => $row['metadata_fingerprint'],
			'created_at'                 => $createdAt,
			'last_activity_at'           => $lastActivity,
			'authorized_at'              => $authorizedAt,
		);
	}

	/**
	 * Projects one active protocol client.
	 *
	 * @param array<string,mixed> $record Validated record.
	 * @phpstan-param StoredClientRecord $record
	 */
	private static function clientFromRecord( array $record ): Client {
		return new Client(
			$record['issuer'],
			$record['client_id'],
			$record['client_name'],
			$record['redirect_uris'],
			$record['token_endpoint_auth_method'],
			$record['grant_types'],
			$record['client_secret_hash'],
			$record['source'],
			$record['metadata_fingerprint']
		);
	}

	/**
	 * Projects one administrator-visible registration.
	 *
	 * @param array<string,mixed> $record Validated record.
	 * @phpstan-param StoredClientRecord $record
	 */
	private static function registrationProjection( array $record ): ClientRegistrationRecord {
		return new ClientRegistrationRecord(
			$record['issuer'],
			$record['client_id'],
			$record['client_name'],
			$record['redirect_uris'],
			$record['status'],
			$record['source'],
			$record['token_endpoint_auth_method'],
			$record['grant_types'],
			$record['metadata_fingerprint'],
			$record['created_at'],
			$record['last_activity_at'],
			$record['authorized_at']
		);
	}

	/**
	 * Compares immutable security metadata.
	 *
	 * @param array<string,mixed> $existing Existing record.
	 * @param array<string,mixed> $candidate Candidate record.
	 * @phpstan-param StoredClientRecord $existing
	 * @phpstan-param ClientIdentityRecord $candidate
	 */
	private static function sameSecurityIdentity( array $existing, array $candidate ): bool {
		return $existing['issuer'] === $candidate['issuer']
			&& $existing['client_id'] === $candidate['client_id']
			&& $existing['client_name'] === $candidate['client_name']
			&& $existing['redirect_uris'] === $candidate['redirect_uris']
			&& $existing['token_endpoint_auth_method'] === $candidate['token_endpoint_auth_method']
			&& $existing['grant_types'] === $candidate['grant_types']
			&& $existing['client_secret_hash'] === $candidate['client_secret_hash'];
	}

	/**
	 * Serializes security metadata deterministically.
	 *
	 * @param string        $name Client name.
	 * @param array<string> $redirectUris Exact redirects.
	 * @param string        $method Authentication method.
	 * @param array<string> $grantTypes Grant types.
	 */
	private static function securityIdentityJson( string $name, array $redirectUris, string $method, array $grantTypes ): string {
		return self::jsonEncode(
			array(
				'name'          => $name,
				'redirect_uris' => $redirectUris,
				'method'        => $method,
				'grant_types'   => $grantTypes,
			)
		);
	}

	/**
	 * Encodes one bounded storage value.
	 *
	 * @param mixed $value Value to encode.
	 * @throws RuntimeException When encoding fails.
	 */
	private static function jsonEncode( mixed $value ): string {
		$json = wp_json_encode( $value, JSON_UNESCAPED_SLASHES );
		if ( ! is_string( $json ) ) {
			throw new RuntimeException( 'charter_client_serialization_failed' );
		}

		return $json;
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
	 * Converts one database integer.
	 *
	 * @param mixed $value Database value.
	 */
	private static function integerValue( mixed $value ): ?int {
		return is_int( $value ) && 0 <= $value
			? $value
			: ( is_string( $value ) && ctype_digit( $value ) ? (int) $value : null );
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

	/**
	 * Encodes random bytes without padding.
	 *
	 * @param string $bytes Random bytes.
	 */
	private static function base64UrlEncode( string $bytes ): string {
		return rtrim( strtr( base64_encode( $bytes ), '+/', '-_' ), '=' ); // phpcs:ignore WordPress.PHP.DiscouragedPHPFunctions.obfuscation_base64_encode -- RFC 4648 URL-safe encoding of random secret bytes.
	}
}
