<?php
/**
 * OAuth grant and credential persistence.
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
 * Stores authoritative grants and only keyed credential digests.
 *
 * @since 0.1.0
 */
final class CredentialStore {

	public const AUTHORIZATION_REQUEST = 'authorization_request';
	public const AUTHORIZATION_CODE    = 'authorization_code';
	public const ACCESS_TOKEN          = 'access_token';
	public const REFRESH_TOKEN         = 'refresh_token';

	private const ACCESS_LIFETIME             = 3600;
	private const REFRESH_INACTIVITY_LIFETIME = 7776000;
	private const REFRESH_ABSOLUTE_LIFETIME   = 31536000;

	/**
	 * Creates the lifecycle store.
	 *
	 * @since 0.1.0
	 *
	 * @param CredentialHasher        $hasher Credential digest service.
	 * @param TransactionManager|null $transactions Owned transaction service.
	 */
	public function __construct(
		private readonly CredentialHasher $hasher,
		?TransactionManager $transactions = null
	) {
		$this->transactions = $transactions ?? new TransactionManager();
	}

	/**
	 * Owned transaction service.
	 *
	 * @var TransactionManager
	 */
	private readonly TransactionManager $transactions;

	/**
	 * Issues a ten-minute, single-use browser authorization transaction.
	 *
	 * @since 0.1.0
	 *
	 * @param AuthorizationRequest $request Validated authorization request.
	 * @param int                  $userId Authorizing WordPress user.
	 * @param int                  $timestamp Current Unix timestamp.
	 */
	public function issueAuthorizationRequest( AuthorizationRequest $request, int $userId, int $timestamp ): string {
		return $this->issue(
			self::AUTHORIZATION_REQUEST,
			$request->issuer(),
			$request->resource(),
			$request->client()->clientId(),
			$request->redirectUri(),
			$userId,
			$request->scope(),
			$request->codeChallenge(),
			$request->state(),
			$timestamp + 600,
			$timestamp,
			'chr_',
			null,
			null,
			$request->continuingAccessRequested()
		);
	}

	/**
	 * Atomically approves a transaction, creates its grant, and issues a code.
	 *
	 * @since 0.1.0
	 *
	 * @param CredentialRecord $transaction Validated authorization transaction.
	 * @param int              $timestamp Current Unix timestamp.
	 * @param int|null         $reusableGrantId Exact prior grant when consent is reusable.
	 * @return string|null Opaque authorization code, or null after a lost race.
	 */
	public function approveAuthorization( CredentialRecord $transaction, int $timestamp, ?int $reusableGrantId = null ): ?string {
		$code       = 'chc_' . self::base64UrlEncode( random_bytes( 32 ) );
		$codeDigest = $this->hasher->digest( $transaction->issuer(), self::AUTHORIZATION_CODE, $code );

		$approved = $this->transactions->run(
			function ( mysqli $database ) use ( $transaction, $timestamp, $codeDigest, $reusableGrantId ): bool {
				$current = $this->lockCredential( $database, $transaction->id() );
				if ( null === $current || ! $this->sameCredential( $transaction, $current ) || ! $current->isActiveAt( $timestamp ) ) {
					return false;
				}

				if ( is_int( $reusableGrantId ) ) {
					$grant = $this->lockGrant( $database, $reusableGrantId );
					if (
						null === $grant
						|| ! $this->grantMatchesAuthorization( $grant, $current )
						|| ! $grant->isActiveAt( $timestamp, $current->continuingAccess() )
					) {
						return false;
					}
					$grantId = $grant->id();
				} else {
					$grantId = $this->insertGrant( $database, $current, $timestamp );
				}

				$this->consumeCredential( $database, $current->id(), $timestamp );
				$this->insertCredential(
					$database,
					self::AUTHORIZATION_CODE,
					$codeDigest,
					$current->issuer(),
					$current->resource(),
					$current->clientId(),
					$current->redirectUri(),
					$current->userId(),
					$current->scope(),
					$current->codeChallenge(),
					null,
					$timestamp + 300,
					$timestamp,
					$grantId,
					null,
					$current->continuingAccess()
				);

				return true;
			}
		);

		return true === $approved ? $code : null;
	}

	/**
	 * Finds a prior exact authorization that can suppress a repeated prompt.
	 *
	 * The returned grant is a preflight hint. Approval locks and revalidates it
	 * in the same transaction that consumes the browser transaction and issues
	 * the authorization code.
	 *
	 * @since 0.1.0
	 *
	 * @param AuthorizationRequest $request Validated authorization request.
	 * @param int                  $userId Represented WordPress user.
	 * @param int                  $timestamp Current Unix timestamp.
	 */
	public function findReusableGrant( AuthorizationRequest $request, int $userId, int $timestamp ): ?GrantRecord {
		if ( $userId <= 0 ) {
			return null;
		}

		return $this->transactions->run(
			function ( mysqli $database ) use ( $request, $userId, $timestamp ): ?GrantRecord {
				$table  = self::quotedTable( Schema::grantTable() );
				$result = $database->execute_query(
					"SELECT id,issuer,resource,client_id,redirect_uri,user_id,scope,continuing_access,status,authorized_at,last_used_at,refresh_absolute_expires_at,refresh_inactivity_expires_at
					FROM {$table}
					WHERE client_digest = ? AND user_id = ? AND status = 'active'
					ORDER BY authorized_at DESC, id DESC LIMIT 50",
					array( self::clientDigest( $request->issuer(), $request->client()->clientId() ), $userId )
				); // phpcs:ignore WordPress.DB.RestrictedFunctions.mysql_mysqli -- Authoritative consent reads use an owned non-reconnecting connection.
				if ( ! $result instanceof mysqli_result ) {
					throw new RuntimeException( 'charter_database_query_failed' );
				}

				while ( true ) {
					$row = $result->fetch_assoc();
					if ( ! is_array( $row ) ) {
						break;
					}
					$grant = $this->grantFromRow( $row );
					if (
						null !== $grant
						&& $grant->issuer() === $request->issuer()
						&& $grant->resource() === $request->resource()
						&& $grant->clientId() === $request->client()->clientId()
						&& $grant->redirectUri() === $request->redirectUri()
						&& $grant->userId() === $userId
						&& $grant->scope() === $request->scope()
						&& $grant->continuingAccess() === $request->continuingAccessRequested()
						&& $grant->isActiveAt( $timestamp, $request->continuingAccessRequested() )
					) {
						$result->free();

						return $grant;
					}
				}
				$result->free();

				return null;
			}
		);
	}

	/**
	 * Atomically consumes a code and issues its bound access credentials.
	 *
	 * @since 0.1.0
	 *
	 * @param CredentialRecord $code Validated authorization code.
	 * @param int              $timestamp Current Unix timestamp.
	 * @return array{access_token: string, refresh_token?: string}|null Issued values or null when invalid/replayed.
	 */
	public function exchangeAuthorizationCode( CredentialRecord $code, int $timestamp ): ?array {
		$grantId = $code->grantId();
		if ( null === $grantId ) {
			return null;
		}

		$accessToken   = 'cha_' . self::base64UrlEncode( random_bytes( 32 ) );
		$accessDigest  = $this->hasher->digest( $code->issuer(), self::ACCESS_TOKEN, $accessToken );
		$refreshToken  = $code->continuingAccess() ? 'chf_' . self::base64UrlEncode( random_bytes( 32 ) ) : null;
		$refreshDigest = is_string( $refreshToken )
			? $this->hasher->digest( $code->issuer(), self::REFRESH_TOKEN, $refreshToken )
			: null;

		$issued = $this->transactions->run(
			function ( mysqli $database ) use ( $code, $grantId, $timestamp, $accessDigest, $refreshDigest ): bool {
				$grant   = $this->lockGrant( $database, $grantId );
				$current = $this->lockCredential( $database, $code->id() );
				if ( null === $grant || null === $current || ! $this->sameCredential( $code, $current ) || ! $this->grantMatchesCredential( $grant, $current ) ) {
					return false;
				}

				if ( null !== $current->consumedAt() ) {
					$this->deactivateGrant( $database, $grantId, $timestamp, 'revoked', 'authorization_code_replay' );
					return false;
				}

				if ( ! $current->isActiveAt( $timestamp ) || ! $grant->isActiveAt( $timestamp ) ) {
					return false;
				}

				$this->consumeCredential( $database, $current->id(), $timestamp );
				$this->insertCredential(
					$database,
					self::ACCESS_TOKEN,
					$accessDigest,
					$grant->issuer(),
					$grant->resource(),
					$grant->clientId(),
					$grant->redirectUri(),
					$grant->userId(),
					$grant->scope(),
					'',
					null,
					$timestamp + self::ACCESS_LIFETIME,
					$timestamp,
					$grantId,
					null,
					$grant->continuingAccess()
				);

				if ( is_string( $refreshDigest ) ) {
					$absoluteExpiry = $grant->refreshAbsoluteExpiresAt();
					if ( ! is_int( $absoluteExpiry ) ) {
						throw new RuntimeException( 'charter_refresh_grant_invalid' );
					}
					$this->insertCredential(
						$database,
						self::REFRESH_TOKEN,
						$refreshDigest,
						$grant->issuer(),
						$grant->resource(),
						$grant->clientId(),
						$grant->redirectUri(),
						$grant->userId(),
						$grant->scope(),
						'',
						null,
						min( $absoluteExpiry, $timestamp + self::REFRESH_INACTIVITY_LIFETIME ),
						$timestamp,
						$grantId,
						null,
						true
					);
				}

				$this->touchGrant( $database, $grantId, $timestamp, $grant->continuingAccess() );

				return true;
			}
		);

		if ( true !== $issued ) {
			return null;
		}

		$result = array( 'access_token' => $accessToken );
		if ( is_string( $refreshToken ) ) {
			$result['refresh_token'] = $refreshToken;
		}

		return $result;
	}

	/**
	 * Atomically rotates one refresh member and issues a new access token.
	 *
	 * @since 0.1.0
	 *
	 * @param CredentialRecord $refreshToken Validated refresh member.
	 * @param int              $timestamp Current Unix timestamp.
	 * @return array{access_token: string, refresh_token: string}|null Issued values or null when invalid/replayed.
	 */
	public function rotateRefreshToken( CredentialRecord $refreshToken, int $timestamp ): ?array {
		$grantId = $refreshToken->grantId();
		if ( null === $grantId ) {
			return null;
		}

		$nextAccess    = 'cha_' . self::base64UrlEncode( random_bytes( 32 ) );
		$nextRefresh   = 'chf_' . self::base64UrlEncode( random_bytes( 32 ) );
		$accessDigest  = $this->hasher->digest( $refreshToken->issuer(), self::ACCESS_TOKEN, $nextAccess );
		$refreshDigest = $this->hasher->digest( $refreshToken->issuer(), self::REFRESH_TOKEN, $nextRefresh );

		$rotated = $this->transactions->run(
			function ( mysqli $database ) use ( $refreshToken, $grantId, $timestamp, $accessDigest, $refreshDigest ): bool {
				$grant   = $this->lockGrant( $database, $grantId );
				$current = $this->lockCredential( $database, $refreshToken->id() );
				if ( null === $grant || null === $current || ! $this->sameCredential( $refreshToken, $current ) || ! $this->grantMatchesCredential( $grant, $current ) ) {
					return false;
				}

				if ( null !== $current->consumedAt() ) {
					$this->deactivateGrant( $database, $grantId, $timestamp, 'revoked', 'refresh_token_replay' );
					return false;
				}

				if ( ! $current->isActiveAt( $timestamp ) || ! $grant->isActiveAt( $timestamp, true ) ) {
					$this->deactivateGrant( $database, $grantId, $timestamp, 'expired', 'refresh_grant_expired' );
					return false;
				}

				$absoluteExpiry = $grant->refreshAbsoluteExpiresAt();
				if ( ! is_int( $absoluteExpiry ) ) {
					throw new RuntimeException( 'charter_refresh_grant_invalid' );
				}
				$nextRefreshExpiry = min( $absoluteExpiry, $timestamp + self::REFRESH_INACTIVITY_LIFETIME );

				$this->consumeCredential( $database, $current->id(), $timestamp );
				$this->insertCredential(
					$database,
					self::ACCESS_TOKEN,
					$accessDigest,
					$grant->issuer(),
					$grant->resource(),
					$grant->clientId(),
					$grant->redirectUri(),
					$grant->userId(),
					$grant->scope(),
					'',
					null,
					$timestamp + self::ACCESS_LIFETIME,
					$timestamp,
					$grantId,
					null,
					true
				);
				$this->insertCredential(
					$database,
					self::REFRESH_TOKEN,
					$refreshDigest,
					$grant->issuer(),
					$grant->resource(),
					$grant->clientId(),
					$grant->redirectUri(),
					$grant->userId(),
					$grant->scope(),
					'',
					null,
					$nextRefreshExpiry,
					$timestamp,
					$grantId,
					$current->id(),
					true
				);
				$this->touchGrant( $database, $grantId, $timestamp, true );

				return true;
			}
		);

		return true === $rotated
			? array(
				'access_token'  => $nextAccess,
				'refresh_token' => $nextRefresh,
			)
			: null;
	}

	/**
	 * Finds a credential by its presented opaque value and exact issuer.
	 *
	 * @since 0.1.0
	 *
	 * @param string $type Expected credential type.
	 * @param string $issuer Exact current issuer.
	 * @param string $credential Presented credential.
	 * @throws RuntimeException When hashing or database access fails.
	 */
	public function find( string $type, string $issuer, string $credential ): ?CredentialRecord {
		if ( '' === $credential || strlen( $credential ) > 256 ) {
			return null;
		}

		$digest = $this->hasher->digest( $issuer, $type, $credential );

		return $this->transactions->run(
			fn ( mysqli $database ): ?CredentialRecord => $this->selectCredential( $database, $type, $digest )
		);
	}

	/**
	 * Finds one authoritative grant by identifier.
	 *
	 * @since 0.1.0
	 *
	 * @param int $grantId Grant identifier.
	 * @throws RuntimeException When database access fails.
	 */
	public function findGrant( int $grantId ): ?GrantRecord {
		if ( $grantId <= 0 ) {
			return null;
		}

		return $this->transactions->run(
			fn ( mysqli $database ): ?GrantRecord => $this->selectGrant( $database, $grantId )
		);
	}

	/**
	 * Lists active authorizations owned by one exact current-site user.
	 *
	 * @since 0.1.0
	 *
	 * @param string $issuer Exact current issuer.
	 * @param int    $userId Represented WordPress user.
	 * @return array<GrantRecord> Most recently active grants first.
	 * @throws RuntimeException When database access fails.
	 */
	public function listActiveGrantsForUser( string $issuer, int $userId ): array {
		if ( '' === $issuer || $userId <= 0 ) {
			return array();
		}
		$timestamp = time();

		return $this->transactions->run(
			function ( mysqli $database ) use ( $issuer, $userId, $timestamp ): array {
				$table  = self::quotedTable( Schema::grantTable() );
				$result = $database->execute_query(
					"SELECT id,issuer,resource,client_id,redirect_uri,user_id,scope,continuing_access,status,authorized_at,last_used_at,refresh_absolute_expires_at,refresh_inactivity_expires_at
					FROM {$table}
					WHERE issuer = ? AND user_id = ? AND status = 'active'
					ORDER BY last_used_at DESC, id DESC LIMIT 500",
					array( $issuer, $userId )
				); // phpcs:ignore WordPress.DB.RestrictedFunctions.mysql_mysqli -- The personal authorization view uses an owned non-reconnecting connection.
				if ( ! $result instanceof mysqli_result ) {
					throw new RuntimeException( 'charter_database_query_failed' );
				}

				$grants = array();
				while ( true ) {
					$row = $result->fetch_assoc();
					if ( ! is_array( $row ) ) {
						break;
					}
					$grant = $this->grantFromRow( $row );
					if (
						null !== $grant
						&& $grant->issuer() === $issuer
						&& $grant->userId() === $userId
						&& $grant->isActiveAt( $timestamp, $grant->continuingAccess() )
					) {
						$grants[] = $grant;
					}
				}
				$result->free();

				return $grants;
			}
		);
	}

	/**
	 * Atomically consumes a still-active non-authority transaction.
	 *
	 * @since 0.1.0
	 *
	 * @param CredentialRecord $record Credential selected by digest.
	 * @param int              $timestamp Current Unix timestamp.
	 * @throws RuntimeException When database access fails.
	 */
	public function consume( CredentialRecord $record, int $timestamp ): bool {
		return $this->transactions->run(
			function ( mysqli $database ) use ( $record, $timestamp ): bool {
				$current = $this->lockCredential( $database, $record->id() );
				if ( null === $current || ! $this->sameCredential( $record, $current ) || ! $current->isActiveAt( $timestamp ) ) {
					return false;
				}

				$this->consumeCredential( $database, $record->id(), $timestamp );

				return true;
			}
		);
	}

	/**
	 * Revokes a complete grant and every active credential descendant.
	 *
	 * @since 0.1.0
	 *
	 * @throws RuntimeException When grant revocation fails.
	 *
	 * @param int    $grantId Grant identifier.
	 * @param int    $timestamp Current Unix timestamp.
	 * @param string $reason Stable non-secret reason.
	 */
	public function revokeGrant( int $grantId, int $timestamp, string $reason ): bool {
		if ( $grantId <= 0 || 1 !== preg_match( '/^[a-z0-9_]{1,64}$/D', $reason ) ) {
			return false;
		}

		return $this->transactions->run(
			function ( mysqli $database ) use ( $grantId, $timestamp, $reason ): bool {
				if ( null === $this->lockGrant( $database, $grantId ) ) {
					return false;
				}

				$this->deactivateGrant( $database, $grantId, $timestamp, 'revoked', $reason );

				return true;
			}
		);
	}

	/**
	 * Revokes every active grant for one user under one exact site issuer.
	 *
	 * @since 0.1.0
	 *
	 * @param string $issuer Exact current site issuer.
	 * @param int    $userId Represented WordPress user.
	 * @param int    $timestamp Current Unix timestamp.
	 * @param string $reason Stable non-secret reason.
	 * @return int Number of active grants closed.
	 * @throws RuntimeException When grant revocation fails.
	 */
	public function revokeAllGrantsForUser( string $issuer, int $userId, int $timestamp, string $reason ): int {
		if ( '' === $issuer || $userId <= 0 || 1 !== preg_match( '/^[a-z0-9_]{1,64}$/D', $reason ) ) {
			return 0;
		}

		return $this->transactions->run(
			function ( mysqli $database ) use ( $issuer, $userId, $timestamp, $reason ): int {
				$table  = self::quotedTable( Schema::grantTable() );
				$result = $database->execute_query(
					"SELECT id FROM {$table} WHERE user_id = ? AND status = 'active' FOR UPDATE",
					array( $userId )
				); // phpcs:ignore WordPress.DB.RestrictedFunctions.mysql_mysqli -- Deterministic user revocation uses an owned non-reconnecting transaction.
				if ( ! $result instanceof mysqli_result ) {
					throw new RuntimeException( 'charter_database_query_failed' );
				}

				$grantIds = array();
				while ( true ) {
					$row = $result->fetch_assoc();
					if ( ! is_array( $row ) ) {
						break;
					}
					$grantId = self::integerValue( $row['id'] ?? null );
					if ( is_int( $grantId ) && $grantId > 0 ) {
						$grantIds[] = $grantId;
					}
				}
				$result->free();

				$revoked = 0;
				foreach ( $grantIds as $grantId ) {
					$grant = $this->lockGrant( $database, $grantId );
					if ( null === $grant || $grant->issuer() !== $issuer || $grant->userId() !== $userId || 'active' !== $grant->status() ) {
						continue;
					}
					$this->deactivateGrant( $database, $grantId, $timestamp, 'revoked', $reason );
					++$revoked;
				}

				return $revoked;
			}
		);
	}

	/**
	 * Deletes current-site credential and grant records during tests/uninstall.
	 *
	 * @since 0.1.0
	 *
	 * @throws RuntimeException When database cleanup fails.
	 */
	public function deleteAll(): void {
		$this->transactions->run(
			static function ( mysqli $database ): void {
				foreach ( array( Schema::credentialTable(), Schema::grantTable() ) as $table ) {
					$quoted = self::quotedTable( $table );
					$database->query( "DELETE FROM {$quoted}" ); // phpcs:ignore WordPress.DB.RestrictedFunctions.mysql_mysqli -- Owned cleanup transaction cannot use the reconnecting global wpdb connection.
				}
			}
		);
	}

	/**
	 * Issues one high-entropy credential through ordinary WordPress persistence.
	 *
	 * @param string      $type Credential type.
	 * @param string      $issuer Exact issuer.
	 * @param string      $resourceIdentifier Exact resource.
	 * @param string      $clientId Exact client identifier.
	 * @param string      $redirectUri Exact redirect URI.
	 * @param int         $userId Represented user.
	 * @param string      $scope Canonical scope string.
	 * @param string      $codeChallenge S256 challenge.
	 * @param string|null $requestState Optional request state.
	 * @param int         $expiresAt Expiry timestamp.
	 * @param int         $createdAt Creation timestamp.
	 * @param string      $prefix Credential prefix.
	 * @param int|null    $grantId Owning grant.
	 * @param int|null    $parentId Refresh parent.
	 * @param bool        $continuingAccess Continuing-access choice.
	 * @throws RuntimeException When secure credential issuance fails.
	 */
	private function issue( string $type, string $issuer, string $resourceIdentifier, string $clientId, string $redirectUri, int $userId, string $scope, string $codeChallenge, ?string $requestState, int $expiresAt, int $createdAt, string $prefix, ?int $grantId, ?int $parentId, bool $continuingAccess ): string {
		$credential = $prefix . self::base64UrlEncode( random_bytes( 32 ) );
		$digest     = $this->hasher->digest( $issuer, $type, $credential );
		$this->transactions->run(
			function ( mysqli $database ) use ( $type, $digest, $issuer, $resourceIdentifier, $clientId, $redirectUri, $userId, $scope, $codeChallenge, $requestState, $expiresAt, $createdAt, $grantId, $parentId, $continuingAccess ): void {
				$this->insertCredential( $database, $type, $digest, $issuer, $resourceIdentifier, $clientId, $redirectUri, $userId, $scope, $codeChallenge, $requestState, $expiresAt, $createdAt, $grantId, $parentId, $continuingAccess );
			}
		);

		return $credential;
	}

	/**
	 * Inserts one credential within an owned lifecycle transaction.
	 *
	 * @param mysqli      $database Owned connection.
	 * @param string      $type Credential type.
	 * @param string      $digest One-way credential digest.
	 * @param string      $issuer Exact issuer.
	 * @param string      $resourceIdentifier Exact resource.
	 * @param string      $clientId Exact client.
	 * @param string      $redirectUri Exact redirect.
	 * @param int         $userId Represented user.
	 * @param string      $scope Canonical scope.
	 * @param string      $codeChallenge S256 challenge.
	 * @param string|null $requestState Optional state.
	 * @param int         $expiresAt Expiry timestamp.
	 * @param int         $createdAt Creation timestamp.
	 * @param int|null    $grantId Grant identifier.
	 * @param int|null    $parentId Refresh parent identifier.
	 * @param bool        $continuingAccess Continuing-access choice.
	 * @throws RuntimeException When credential insertion fails.
	 */
	private function insertCredential( mysqli $database, string $type, string $digest, string $issuer, string $resourceIdentifier, string $clientId, string $redirectUri, int $userId, string $scope, string $codeChallenge, ?string $requestState, int $expiresAt, int $createdAt, ?int $grantId, ?int $parentId, bool $continuingAccess ): void {
		$table  = self::quotedTable( Schema::credentialTable() );
		$result = $database->execute_query(
			"INSERT INTO {$table}
			(credential_type,digest,issuer,resource,client_id,redirect_uri,user_id,scope,code_challenge,request_state,expires_at,consumed_at,created_at,grant_id,parent_id,continuing_access)
			VALUES (?,?,?,?,?,?,?,?,?,?,?,NULL,?,?,?,?)",
			array( $type, $digest, $issuer, $resourceIdentifier, $clientId, $redirectUri, $userId, $scope, $codeChallenge, $requestState, $expiresAt, $createdAt, $grantId, $parentId, $continuingAccess ? 1 : 0 )
		); // phpcs:ignore WordPress.DB.RestrictedFunctions.mysql_mysqli -- Owned transaction SQL cannot use the reconnecting global wpdb connection.
		if ( true !== $result || 1 !== $database->affected_rows ) {
			throw new RuntimeException( 'charter_credential_issuance_failed' );
		}
	}

	/**
	 * Inserts an approved grant and returns its identifier.
	 *
	 * @param mysqli           $database Owned connection.
	 * @param CredentialRecord $transaction Approved transaction.
	 * @param int              $timestamp Current Unix timestamp.
	 * @throws RuntimeException When grant insertion fails.
	 */
	private function insertGrant( mysqli $database, CredentialRecord $transaction, int $timestamp ): int {
		$table            = self::quotedTable( Schema::grantTable() );
		$absoluteExpiry   = $transaction->continuingAccess() ? $timestamp + self::REFRESH_ABSOLUTE_LIFETIME : null;
		$inactivityExpiry = $transaction->continuingAccess() ? $timestamp + self::REFRESH_INACTIVITY_LIFETIME : null;
		$result           = $database->execute_query(
			"INSERT INTO {$table}
			(issuer,resource,client_id,client_digest,redirect_uri,user_id,scope,continuing_access,status,authorized_at,last_used_at,refresh_absolute_expires_at,refresh_inactivity_expires_at,revoked_at,revocation_reason)
			VALUES (?,?,?,?,?,?,?,?, 'active', ?,?,?,?,NULL,NULL)",
			array(
				$transaction->issuer(),
				$transaction->resource(),
				$transaction->clientId(),
				self::clientDigest( $transaction->issuer(), $transaction->clientId() ),
				$transaction->redirectUri(),
				$transaction->userId(),
				$transaction->scope(),
				$transaction->continuingAccess() ? 1 : 0,
				$timestamp,
				$timestamp,
				$absoluteExpiry,
				$inactivityExpiry,
			)
		); // phpcs:ignore WordPress.DB.RestrictedFunctions.mysql_mysqli -- Owned transaction SQL cannot use the reconnecting global wpdb connection.
		if ( true !== $result || 1 !== $database->affected_rows || ! is_int( $database->insert_id ) || $database->insert_id <= 0 ) {
			throw new RuntimeException( 'charter_grant_issuance_failed' );
		}

		return $database->insert_id;
	}

	/**
	 * Loads one credential by its exact type-separated digest.
	 *
	 * @param mysqli $database Owned connection.
	 * @param string $type Credential type.
	 * @param string $digest One-way credential digest.
	 * @throws RuntimeException When the query fails.
	 */
	private function selectCredential( mysqli $database, string $type, string $digest ): ?CredentialRecord {
		$table  = self::quotedTable( Schema::credentialTable() );
		$result = $database->execute_query(
			"SELECT id,credential_type,issuer,resource,client_id,redirect_uri,user_id,scope,code_challenge,request_state,expires_at,consumed_at,grant_id,parent_id,continuing_access FROM {$table} WHERE credential_type = ? AND digest = ? LIMIT 1",
			array( $type, $digest )
		); // phpcs:ignore WordPress.DB.RestrictedFunctions.mysql_mysqli -- Authoritative credential reads use an owned non-reconnecting connection.
		if ( ! $result instanceof mysqli_result ) {
			throw new RuntimeException( 'charter_database_query_failed' );
		}
		$row = $result->fetch_assoc();
		$result->free();

		return is_array( $row ) ? $this->recordFromRow( $row ) : null;
	}

	/**
	 * Loads one grant by its database identifier.
	 *
	 * @param mysqli $database Owned connection.
	 * @param int    $grantId Grant identifier.
	 * @throws RuntimeException When the query fails.
	 */
	private function selectGrant( mysqli $database, int $grantId ): ?GrantRecord {
		$table  = self::quotedTable( Schema::grantTable() );
		$result = $database->execute_query(
			"SELECT id,issuer,resource,client_id,redirect_uri,user_id,scope,continuing_access,status,authorized_at,last_used_at,refresh_absolute_expires_at,refresh_inactivity_expires_at FROM {$table} WHERE id = ? LIMIT 1",
			array( $grantId )
		); // phpcs:ignore WordPress.DB.RestrictedFunctions.mysql_mysqli -- Authoritative grant reads use an owned non-reconnecting connection.
		if ( ! $result instanceof mysqli_result ) {
			throw new RuntimeException( 'charter_database_query_failed' );
		}
		$row = $result->fetch_assoc();
		$result->free();

		return is_array( $row ) ? $this->grantFromRow( $row ) : null;
	}

	/**
	 * Locks and loads one credential row.
	 *
	 * @param mysqli $database Owned connection.
	 * @param int    $credentialId Credential identifier.
	 * @throws RuntimeException When the query fails.
	 */
	private function lockCredential( mysqli $database, int $credentialId ): ?CredentialRecord {
		$table  = self::quotedTable( Schema::credentialTable() );
		$result = $database->execute_query(
			"SELECT id,credential_type,issuer,resource,client_id,redirect_uri,user_id,scope,code_challenge,request_state,expires_at,consumed_at,grant_id,parent_id,continuing_access FROM {$table} WHERE id = ? FOR UPDATE",
			array( $credentialId )
		); // phpcs:ignore WordPress.DB.RestrictedFunctions.mysql_mysqli -- Owned transaction SQL cannot use the reconnecting global wpdb connection.
		if ( ! $result instanceof mysqli_result ) {
			throw new RuntimeException( 'charter_database_query_failed' );
		}
		$row = $result->fetch_assoc();
		$result->free();

		return is_array( $row ) ? $this->recordFromRow( $row ) : null;
	}

	/**
	 * Locks and loads one grant row.
	 *
	 * @param mysqli $database Owned connection.
	 * @param int    $grantId Grant identifier.
	 * @throws RuntimeException When the query fails.
	 */
	private function lockGrant( mysqli $database, int $grantId ): ?GrantRecord {
		$table  = self::quotedTable( Schema::grantTable() );
		$result = $database->execute_query(
			"SELECT id,issuer,resource,client_id,redirect_uri,user_id,scope,continuing_access,status,authorized_at,last_used_at,refresh_absolute_expires_at,refresh_inactivity_expires_at FROM {$table} WHERE id = ? FOR UPDATE",
			array( $grantId )
		); // phpcs:ignore WordPress.DB.RestrictedFunctions.mysql_mysqli -- Owned transaction SQL cannot use the reconnecting global wpdb connection.
		if ( ! $result instanceof mysqli_result ) {
			throw new RuntimeException( 'charter_database_query_failed' );
		}
		$row = $result->fetch_assoc();
		$result->free();

		return is_array( $row ) ? $this->grantFromRow( $row ) : null;
	}

	/**
	 * Retires one locked credential.
	 *
	 * @param mysqli $database Owned connection.
	 * @param int    $credentialId Credential identifier.
	 * @param int    $timestamp Current Unix timestamp.
	 * @throws RuntimeException When the transition loses its single-winner boundary.
	 */
	private function consumeCredential( mysqli $database, int $credentialId, int $timestamp ): void {
		$table  = self::quotedTable( Schema::credentialTable() );
		$result = $database->execute_query(
			"UPDATE {$table} SET consumed_at = ? WHERE id = ? AND consumed_at IS NULL",
			array( $timestamp, $credentialId )
		); // phpcs:ignore WordPress.DB.RestrictedFunctions.mysql_mysqli -- Owned transaction SQL cannot use the reconnecting global wpdb connection.
		if ( true !== $result || 1 !== $database->affected_rows ) {
			throw new RuntimeException( 'charter_credential_transition_conflict' );
		}
	}

	/**
	 * Updates coarse grant activity and the refresh inactivity boundary.
	 *
	 * @param mysqli $database Owned connection.
	 * @param int    $grantId Grant identifier.
	 * @param int    $timestamp Current Unix timestamp.
	 * @param bool   $refresh Whether refresh inactivity also advances.
	 * @throws RuntimeException When the grant update fails.
	 */
	private function touchGrant( mysqli $database, int $grantId, int $timestamp, bool $refresh ): void {
		$table = self::quotedTable( Schema::grantTable() );
		if ( $refresh ) {
			$result = $database->execute_query(
				"UPDATE {$table} SET last_used_at = ?, refresh_inactivity_expires_at = LEAST(refresh_absolute_expires_at, ?) WHERE id = ? AND status = 'active'",
				array( $timestamp, $timestamp + self::REFRESH_INACTIVITY_LIFETIME, $grantId )
			); // phpcs:ignore WordPress.DB.RestrictedFunctions.mysql_mysqli -- Owned transaction SQL cannot use the reconnecting global wpdb connection.
		} else {
			$result = $database->execute_query(
				"UPDATE {$table} SET last_used_at = ? WHERE id = ? AND status = 'active'",
				array( $timestamp, $grantId )
			); // phpcs:ignore WordPress.DB.RestrictedFunctions.mysql_mysqli -- Owned transaction SQL cannot use the reconnecting global wpdb connection.
		}
		if ( true !== $result ) {
			throw new RuntimeException( 'charter_grant_transition_conflict' );
		}
	}

	/**
	 * Applies one grant-wide terminal transition and closes all descendants.
	 *
	 * @param mysqli $database Owned connection.
	 * @param int    $grantId Grant identifier.
	 * @param int    $timestamp Current Unix timestamp.
	 * @param string $status Terminal grant status.
	 * @param string $reason Stable non-secret reason.
	 * @throws RuntimeException When the transition fails.
	 */
	private function deactivateGrant( mysqli $database, int $grantId, int $timestamp, string $status, string $reason ): void {
		$grant_table      = self::quotedTable( Schema::grantTable() );
		$credential_table = self::quotedTable( Schema::credentialTable() );
		$result           = $database->execute_query(
			"UPDATE {$grant_table} SET status = ?, revoked_at = ?, revocation_reason = ? WHERE id = ? AND status = 'active'",
			array( $status, $timestamp, $reason, $grantId )
		); // phpcs:ignore WordPress.DB.RestrictedFunctions.mysql_mysqli -- Owned transaction SQL cannot use the reconnecting global wpdb connection.
		if ( true !== $result ) {
			throw new RuntimeException( 'charter_grant_revocation_failed' );
		}

		$result = $database->execute_query(
			"UPDATE {$credential_table} SET consumed_at = ? WHERE grant_id = ? AND consumed_at IS NULL",
			array( $timestamp, $grantId )
		); // phpcs:ignore WordPress.DB.RestrictedFunctions.mysql_mysqli -- Owned transaction SQL cannot use the reconnecting global wpdb connection.
		if ( true !== $result ) {
			throw new RuntimeException( 'charter_grant_revocation_failed' );
		}
	}

	/**
	 * Converts a database row into a typed credential record.
	 *
	 * @param array<mixed> $row Database row.
	 */
	private function recordFromRow( array $row ): ?CredentialRecord {
		$requiredStrings = array( 'credential_type', 'issuer', 'resource', 'client_id', 'redirect_uri', 'scope', 'code_challenge' );
		foreach ( $requiredStrings as $field ) {
			if ( ! is_string( $row[ $field ] ?? null ) ) {
				return null;
			}
		}

		$id               = self::integerValue( $row['id'] ?? null );
		$userId           = self::integerValue( $row['user_id'] ?? null );
		$expiresAt        = self::integerValue( $row['expires_at'] ?? null );
		$continuingAccess = self::integerValue( $row['continuing_access'] ?? null );
		if ( null === $id || null === $userId || null === $expiresAt || ! in_array( $continuingAccess, array( 0, 1 ), true ) ) {
			return null;
		}

		$optionalIntegers = array();
		foreach ( array( 'consumed_at', 'grant_id', 'parent_id' ) as $field ) {
			$value        = $row[ $field ] ?? null;
			$integerValue = self::integerValue( $value );
			if ( null !== $value && null === $integerValue ) {
				return null;
			}
			$optionalIntegers[ $field ] = $integerValue;
		}

		$requestState = $row['request_state'] ?? null;

		return new CredentialRecord(
			$id,
			$row['credential_type'],
			$row['issuer'],
			$row['resource'],
			$row['client_id'],
			$row['redirect_uri'],
			$userId,
			$row['scope'],
			$row['code_challenge'],
			is_string( $requestState ) ? $requestState : null,
			$expiresAt,
			$optionalIntegers['consumed_at'],
			$optionalIntegers['grant_id'],
			$optionalIntegers['parent_id'],
			1 === $continuingAccess
		);
	}

	/**
	 * Converts a database row into a typed grant record.
	 *
	 * @param array<mixed> $row Database row.
	 */
	private function grantFromRow( array $row ): ?GrantRecord {
		foreach ( array( 'issuer', 'resource', 'client_id', 'redirect_uri', 'scope', 'status' ) as $field ) {
			if ( ! is_string( $row[ $field ] ?? null ) ) {
				return null;
			}
		}
		$id               = self::integerValue( $row['id'] ?? null );
		$userId           = self::integerValue( $row['user_id'] ?? null );
		$continuingAccess = self::integerValue( $row['continuing_access'] ?? null );
		$authorizedAt     = self::integerValue( $row['authorized_at'] ?? null );
		$lastUsedAt       = self::integerValue( $row['last_used_at'] ?? null );
		if ( null === $id || null === $userId || null === $authorizedAt || null === $lastUsedAt || ! in_array( $continuingAccess, array( 0, 1 ), true ) ) {
			return null;
		}

		$absolute        = $row['refresh_absolute_expires_at'] ?? null;
		$inactivity      = $row['refresh_inactivity_expires_at'] ?? null;
		$absoluteValue   = self::integerValue( $absolute );
		$inactivityValue = self::integerValue( $inactivity );
		if ( ( null !== $absolute && null === $absoluteValue ) || ( null !== $inactivity && null === $inactivityValue ) ) {
			return null;
		}

		return new GrantRecord(
			$id,
			$row['issuer'],
			$row['resource'],
			$row['client_id'],
			$row['redirect_uri'],
			$userId,
			$row['scope'],
			1 === $continuingAccess,
			$row['status'],
			$authorizedAt,
			$lastUsedAt,
			$absoluteValue,
			$inactivityValue
		);
	}

	/**
	 * Compares immutable credential bindings across a transaction lock.
	 *
	 * @param CredentialRecord $expected Pre-lock record.
	 * @param CredentialRecord $current Locked record.
	 */
	private function sameCredential( CredentialRecord $expected, CredentialRecord $current ): bool {
		return $expected->id() === $current->id()
			&& $expected->type() === $current->type()
			&& $expected->issuer() === $current->issuer()
			&& $expected->resource() === $current->resource()
			&& $expected->clientId() === $current->clientId()
			&& $expected->redirectUri() === $current->redirectUri()
			&& $expected->userId() === $current->userId()
			&& $expected->scope() === $current->scope()
			&& $expected->codeChallenge() === $current->codeChallenge()
			&& $expected->grantId() === $current->grantId()
			&& $expected->continuingAccess() === $current->continuingAccess();
	}

	/**
	 * Confirms one credential remains inside its exact grant boundary.
	 *
	 * @param GrantRecord      $grant Authoritative grant.
	 * @param CredentialRecord $credential Credential descendant.
	 */
	private function grantMatchesCredential( GrantRecord $grant, CredentialRecord $credential ): bool {
		return $credential->grantId() === $grant->id()
			&& $credential->issuer() === $grant->issuer()
			&& $credential->resource() === $grant->resource()
			&& $credential->clientId() === $grant->clientId()
			&& $credential->redirectUri() === $grant->redirectUri()
			&& $credential->userId() === $grant->userId()
			&& $credential->scope() === $grant->scope()
			&& $credential->continuingAccess() === $grant->continuingAccess();
	}

	/**
	 * Confirms a prior grant exactly covers a new browser authorization.
	 *
	 * @param GrantRecord      $grant Prior user-approved grant.
	 * @param CredentialRecord $transaction Current browser transaction.
	 */
	private function grantMatchesAuthorization( GrantRecord $grant, CredentialRecord $transaction ): bool {
		return $transaction->issuer() === $grant->issuer()
			&& $transaction->resource() === $grant->resource()
			&& $transaction->clientId() === $grant->clientId()
			&& $transaction->redirectUri() === $grant->redirectUri()
			&& $transaction->userId() === $grant->userId()
			&& $transaction->scope() === $grant->scope()
			&& $transaction->continuingAccess() === $grant->continuingAccess();
	}

	/**
	 * Returns a collision-resistant non-secret issuer/client reference.
	 *
	 * @param string $issuer Exact issuer.
	 * @param string $clientId Exact client identifier.
	 */
	private static function clientDigest( string $issuer, string $clientId ): string {
		return hash( 'sha256', strlen( $issuer ) . ':' . $issuer . strlen( $clientId ) . ':' . $clientId );
	}

	/**
	 * Normalizes native prepared-statement integers and wpdb numeric strings.
	 *
	 * @param mixed $value Database value.
	 */
	private static function integerValue( mixed $value ): ?int {
		if ( is_int( $value ) ) {
			return $value >= 0 ? $value : null;
		}

		return is_string( $value ) && ctype_digit( $value ) ? (int) $value : null;
	}

	/**
	 * Quotes a trusted WordPress-derived table identifier.
	 *
	 * @param string $table Table identifier.
	 * @throws RuntimeException When the identifier is unsafe.
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
		return rtrim( strtr( base64_encode( $bytes ), '+/', '-_' ), '=' ); // phpcs:ignore WordPress.PHP.DiscouragedPHPFunctions.obfuscation_base64_encode -- RFC 4648 URL-safe encoding of random credential bytes, not code obfuscation.
	}
}
