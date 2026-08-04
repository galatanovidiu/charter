<?php
/**
 * Disposable Slice 0 atomic lifecycle transition store.
 *
 * @package GalatanOvidiu\Charter
 */

declare(strict_types=1);

namespace GalatanOvidiu\Charter\Tests\Prototype\AtomicLifecycle;

use JsonException;
use mysqli;
use mysqli_result;
use RuntimeException;

/**
 * Proves observable lifecycle semantics without selecting production storage.
 *
 * @since 0.1.0
 */
final class AtomicLifecycleStore {

	private const PRIMARY_GRANT = 'primary-grant';

	private const PRIMARY_CODE = 'primary-code';

	private const UNKNOWN_CODE = 'unknown-code';

	private const PRIMARY_LINEAGE = 'primary-code-lineage';

	private const PRIMARY_FAMILY = 'primary-family';

	private const UNRELATED_GRANT = 'unrelated-grant';

	private const UNRELATED_FAMILY = 'unrelated-family';

	private const PRIMARY_ISSUER = 'https://primary.example.test';

	private const PRIMARY_RESOURCE = 'https://primary.example.test';

	private const PRIMARY_CLIENT = 'primary-client';

	private const PRIMARY_USER = 101;

	private const PRIMARY_SCOPE = 'wordpress:access';

	private const PRIMARY_INACTIVITY_EXPIRY = 2000000000;

	private const PRIMARY_ABSOLUTE_EXPIRY = 2000003600;

	private const UNRELATED_ISSUER = 'https://unrelated.example.test';

	private const UNRELATED_RESOURCE = 'https://unrelated.example.test';

	private const UNRELATED_CLIENT = 'unrelated-client';

	private const UNRELATED_USER = 202;

	private const UNRELATED_SCOPE = 'wordpress:access unrelated:proof';

	private const UNRELATED_INACTIVITY_EXPIRY = 2000010000;

	private const UNRELATED_ABSOLUTE_EXPIRY = 2000013600;

	/**
	 * Transaction owner for the injected real database connection.
	 *
	 * @var TransactionOwnedConnection
	 */
	private readonly TransactionOwnedConnection $transactions;

	/**
	 * Creates one disposable transition store.
	 *
	 * @param mysqli $database Disposable database connection.
	 */
	public function __construct( private readonly mysqli $database ) {
		$this->transactions = new TransactionOwnedConnection( $database );
	}

	/**
	 * Returns the current sanitized physical connection identifier.
	 */
	public function connectionId(): int {
		return $this->transactions->connectionId();
	}

	/**
	 * Removes every row while leaving disposable DDL available for another case.
	 */
	public function reset(): void {
		foreach ( array_reverse( AtomicLifecycleSchema::tableNames() ) as $table ) {
			$this->outsideExecute( "DELETE FROM {$table}" );
		}
	}

	/**
	 * Seeds one issued code and one unrelated live credential domain.
	 */
	public function seedCodeScenario(): void {
		$this->reset();

		$this->transactions->run(
			function ( TransactionOwnedConnection $transaction ): void {
				$this->insertPrimaryGrant( $transaction );
				$transaction->execute(
					'INSERT INTO ' . AtomicLifecycleSchema::CODES . ' (code_digest, code_id, grant_id, state, lineage_id, expires_at, replay_event_count) VALUES (?, ?, ?, ?, NULL, ?, 0)',
					array(
						self::randomProofDigest(),
						self::PRIMARY_CODE,
						self::PRIMARY_GRANT,
						'issued',
						self::PRIMARY_INACTIVITY_EXPIRY,
					)
				);
				$this->insertUnrelatedDomain( $transaction );
				$this->insertSentinels( $transaction );
			}
		);
	}

	/**
	 * Seeds one current refresh member, two access descendants, and an unrelated domain.
	 */
	public function seedRefreshScenario(): void {
		$this->reset();

		$this->transactions->run(
			function ( TransactionOwnedConnection $transaction ): void {
				$this->insertPrimaryGrant( $transaction );
				$this->insertFamily(
					$transaction,
					self::PRIMARY_FAMILY,
					self::PRIMARY_GRANT,
					null,
					self::PRIMARY_INACTIVITY_EXPIRY,
					self::PRIMARY_ABSOLUTE_EXPIRY
				);
				$this->insertRefreshMember( $transaction, self::PRIMARY_FAMILY, 0, null, 'current' );
				$this->insertAccess( $transaction, self::PRIMARY_GRANT, null, self::PRIMARY_FAMILY, 0, 'primary-seed-a' );
				$this->insertAccess( $transaction, self::PRIMARY_GRANT, null, self::PRIMARY_FAMILY, null, 'primary-seed-b' );
				$this->insertUnrelatedDomain( $transaction );
				$this->insertSentinels( $transaction );
			}
		);
	}

	/**
	 * Exchanges the fixed issued proof code or applies its replay cascade.
	 *
	 * @param TransitionControl|null $control Coordinator and fault control.
	 * @throws TransitionFailure When the complete transaction rolls back.
	 */
	public function exchangeCode( ?TransitionControl $control = null ): TransitionResult {
		$result = $this->transactions->run(
			function ( TransactionOwnedConnection $transaction ) use ( $control ): TransitionResult {
				$this->checkpoint( $control, AtomicLifecycleCheckpoints::BEFORE_CLAIM, $transaction );
				$this->lockGrant( $transaction, self::PRIMARY_GRANT );
				$this->checkpoint( $control, AtomicLifecycleCheckpoints::AFTER_AGGREGATE_LOCK, $transaction );
				$code = $transaction->row(
					'SELECT code_id, state FROM ' . AtomicLifecycleSchema::CODES . ' WHERE code_id = ? FOR UPDATE',
					array( self::PRIMARY_CODE )
				);

				if ( null === $code ) {
					return new TransitionResult(
						TransitionResult::INVALID,
						true,
						$transaction->transactionConnectionId()
					);
				}

				if ( 'issued' !== self::rowString( $code, 'state' ) ) {
					$this->revokeCodeDescendants( $transaction, $control );

					return new TransitionResult(
						TransitionResult::REPLAY,
						true,
						$transaction->transactionConnectionId()
					);
				}

				$transaction->execute(
					'UPDATE ' . AtomicLifecycleSchema::CODES . ' SET state = ?, lineage_id = ? WHERE code_id = ?',
					array( 'consumed', self::PRIMARY_LINEAGE, self::PRIMARY_CODE )
				);
				$this->checkpoint( $control, AtomicLifecycleCheckpoints::AFTER_CLAIM, $transaction );
				$this->insertFamily(
					$transaction,
					self::PRIMARY_FAMILY,
					self::PRIMARY_GRANT,
					self::PRIMARY_CODE,
					self::PRIMARY_INACTIVITY_EXPIRY,
					self::PRIMARY_ABSOLUTE_EXPIRY
				);
				$this->insertRefreshMember( $transaction, self::PRIMARY_FAMILY, 0, null, 'current' );
				$this->insertAccess(
					$transaction,
					self::PRIMARY_GRANT,
					self::PRIMARY_CODE,
					self::PRIMARY_FAMILY,
					0,
					'primary-code-access'
				);
				$this->checkpoint( $control, AtomicLifecycleCheckpoints::AFTER_DESCENDANT, $transaction );

				return new TransitionResult(
					TransitionResult::WINNER,
					true,
					$transaction->transactionConnectionId()
				);
			},
			$control
		);

		$control?->reach( AtomicLifecycleCheckpoints::AFTER_COMMIT, $result->connectionId() );

		return $result;
	}

	/**
	 * Presents a fixed nonexistent code without touching either proof domain.
	 *
	 * @param TransitionControl|null $control Coordinator and fault control.
	 * @throws RuntimeException When the fixed unknown digest unexpectedly exists.
	 */
	public function exchangeUnknownCode( ?TransitionControl $control = null ): TransitionResult {
		$result = $this->transactions->run(
			function ( TransactionOwnedConnection $transaction ) use ( $control ): TransitionResult {
				$this->checkpoint( $control, AtomicLifecycleCheckpoints::BEFORE_CLAIM, $transaction );
				$row = $transaction->row(
					'SELECT code_id FROM ' . AtomicLifecycleSchema::CODES . ' WHERE code_id = ? FOR UPDATE',
					array( self::UNKNOWN_CODE )
				);

				if ( null !== $row ) {
					throw new RuntimeException( 'atomic_lifecycle_unknown_code_collision' );
				}

				return new TransitionResult(
					TransitionResult::INVALID,
					true,
					$transaction->transactionConnectionId()
				);
			},
			$control
		);

		$control?->reach( AtomicLifecycleCheckpoints::AFTER_COMMIT, $result->connectionId() );

		return $result;
	}

	/**
	 * Rotates one fixed generation or treats its retired use as family replay.
	 *
	 * @param int                    $presentedGeneration Fixed member generation.
	 * @param TransitionControl|null $control Coordinator and fault control.
	 * @throws TransitionFailure When the complete transaction rolls back.
	 */
	public function rotateRefresh(
		int $presentedGeneration,
		?TransitionControl $control = null
	): TransitionResult {
		$result = $this->transactions->run(
			function ( TransactionOwnedConnection $transaction ) use ( $presentedGeneration, $control ): TransitionResult {
				$this->checkpoint( $control, AtomicLifecycleCheckpoints::BEFORE_CLAIM, $transaction );
				$this->lockGrant( $transaction, self::PRIMARY_GRANT );
				$this->checkpoint( $control, AtomicLifecycleCheckpoints::AFTER_AGGREGATE_LOCK, $transaction );
				$family = $transaction->row(
					'SELECT state, current_generation FROM ' . AtomicLifecycleSchema::FAMILIES . ' WHERE family_id = ? FOR UPDATE',
					array( self::PRIMARY_FAMILY )
				);

				if ( null === $family ) {
					return new TransitionResult(
						TransitionResult::INVALID,
						true,
						$transaction->transactionConnectionId()
					);
				}

				$member = $transaction->row(
					'SELECT member_digest, state, generation FROM ' . AtomicLifecycleSchema::MEMBERS . ' WHERE family_id = ? AND generation = ? FOR UPDATE',
					array( self::PRIMARY_FAMILY, $presentedGeneration )
				);

				if ( null === $member ) {
					return new TransitionResult(
						TransitionResult::INVALID,
						true,
						$transaction->transactionConnectionId()
					);
				}

				if (
					'active' !== self::rowString( $family, 'state' )
					|| 'current' !== self::rowString( $member, 'state' )
					|| self::rowInt( $family, 'current_generation' ) !== $presentedGeneration
				) {
					$this->revokeRefreshFamily( $transaction, $control );

					return new TransitionResult(
						TransitionResult::REPLAY,
						true,
						$transaction->transactionConnectionId()
					);
				}

				$presentedDigest = self::rowString( $member, 'member_digest' );

				$nextGeneration = $presentedGeneration + 1;
				$transaction->execute(
					'UPDATE ' . AtomicLifecycleSchema::MEMBERS . ' SET state = ? WHERE member_digest = ?',
					array( 'retired', $presentedDigest )
				);
				$this->checkpoint( $control, AtomicLifecycleCheckpoints::AFTER_CLAIM, $transaction );
				$this->insertRefreshMember(
					$transaction,
					self::PRIMARY_FAMILY,
					$nextGeneration,
					$presentedDigest,
					'current'
				);
				$transaction->execute(
					'UPDATE ' . AtomicLifecycleSchema::FAMILIES . ' SET current_generation = ? WHERE family_id = ?',
					array( $nextGeneration, self::PRIMARY_FAMILY )
				);
				$this->insertAccess(
					$transaction,
					self::PRIMARY_GRANT,
					null,
					self::PRIMARY_FAMILY,
					$nextGeneration,
					'primary-refresh-' . $nextGeneration
				);
				$this->checkpoint( $control, AtomicLifecycleCheckpoints::AFTER_DESCENDANT, $transaction );

				return new TransitionResult(
					TransitionResult::WINNER,
					true,
					$transaction->transactionConnectionId()
				);
			},
			$control
		);

		$control?->reach( AtomicLifecycleCheckpoints::AFTER_COMMIT, $result->connectionId() );

		return $result;
	}

	/**
	 * Locks two sentinels in caller-selected order for deadlock/timeout proof.
	 *
	 * @param int                    $firstId First sentinel identifier.
	 * @param int                    $secondId Second sentinel identifier.
	 * @param TransitionControl|null $control Coordinator and fault control.
	 * @throws RuntimeException When a sentinel identifier is unsupported.
	 */
	public function exerciseSentinelTransition(
		int $firstId,
		int $secondId,
		?TransitionControl $control = null
	): TransitionResult {
		if ( ! in_array( $firstId, array( 1, 2 ), true ) || ! in_array( $secondId, array( 1, 2 ), true ) ) {
			throw new RuntimeException( 'atomic_lifecycle_invalid_sentinel' );
		}

		$result = $this->transactions->run(
			function ( TransactionOwnedConnection $transaction ) use ( $firstId, $secondId, $control ): TransitionResult {
				$transaction->row(
					'SELECT value_number FROM ' . AtomicLifecycleSchema::SENTINELS . ' WHERE sentinel_id = ? FOR UPDATE',
					array( $firstId )
				);
				$transaction->execute(
					'UPDATE ' . AtomicLifecycleSchema::SENTINELS . ' SET value_number = value_number + 1 WHERE sentinel_id = ?',
					array( $firstId )
				);
				$this->checkpoint( $control, AtomicLifecycleCheckpoints::AFTER_FIRST_SENTINEL_LOCK, $transaction );
				$transaction->row(
					'SELECT value_number FROM ' . AtomicLifecycleSchema::SENTINELS . ' WHERE sentinel_id = ? FOR UPDATE',
					array( $secondId )
				);

				return new TransitionResult(
					TransitionResult::WINNER,
					true,
					$transaction->transactionConnectionId()
				);
			},
			$control
		);

		$control?->reach( AtomicLifecycleCheckpoints::AFTER_COMMIT, $result->connectionId() );

		return $result;
	}

	/**
	 * Mutates inside a transaction, then pauses before a guarded follow-up query.
	 *
	 * @param TransitionControl|null $control Coordinator and fault control.
	 */
	public function connectionLossTransition( ?TransitionControl $control = null ): TransitionResult {
		$result = $this->transactions->run(
			function ( TransactionOwnedConnection $transaction ) use ( $control ): TransitionResult {
				$transaction->execute(
					'UPDATE ' . AtomicLifecycleSchema::SENTINELS . ' SET value_number = value_number + 1 WHERE sentinel_id = 1'
				);
				$this->checkpoint( $control, AtomicLifecycleCheckpoints::AFTER_CONNECTION_MUTATION, $transaction );
				$transaction->row(
					'SELECT value_number FROM ' . AtomicLifecycleSchema::SENTINELS . ' WHERE sentinel_id = 2 FOR UPDATE'
				);

				return new TransitionResult(
					TransitionResult::WINNER,
					true,
					$transaction->transactionConnectionId()
				);
			},
			$control
		);

		$control?->reach( AtomicLifecycleCheckpoints::AFTER_COMMIT, $result->connectionId() );

		return $result;
	}

	/**
	 * Returns the two harmless rollback sentinels.
	 *
	 * @return array<int, int>
	 */
	public function sentinelValues(): array {
		$rows   = $this->outsideRows(
			'SELECT sentinel_id, value_number FROM ' . AtomicLifecycleSchema::SENTINELS . ' ORDER BY sentinel_id'
		);
		$values = array();

		foreach ( $rows as $row ) {
			$values[ self::rowInt( $row, 'sentinel_id' ) ] = self::rowInt( $row, 'value_number' );
		}

		return $values;
	}

	/**
	 * Returns a sanitized authoritative state snapshot.
	 *
	 * @throws RuntimeException When database state or snapshot encoding is invalid.
	 */
	public function snapshot(): AtomicLifecycleSnapshot {
		$grant  = $this->outsideRow(
			'SELECT issuer, resource_id, client_id, user_id, scope_value, state, inactivity_expires_at, absolute_expires_at FROM ' . AtomicLifecycleSchema::GRANTS . ' WHERE grant_id = ?',
			array( self::PRIMARY_GRANT )
		);
		$code   = $this->outsideRow(
			'SELECT state, replay_event_count FROM ' . AtomicLifecycleSchema::CODES . ' WHERE code_id = ?',
			array( self::PRIMARY_CODE )
		);
		$family = $this->outsideRow(
			'SELECT state, current_generation, inactivity_expires_at, absolute_expires_at FROM ' . AtomicLifecycleSchema::FAMILIES . ' WHERE family_id = ?',
			array( self::PRIMARY_FAMILY )
		);
		$state  = array(
			'code_state'                   => self::rowString( $code, 'state', 'absent' ),
			'grant_state'                  => self::rowString( $grant, 'state', 'absent' ),
			'family_state'                 => self::rowString( $family, 'state', 'absent' ),
			'family_current_generation'    => self::rowInt( $family, 'current_generation', -1 ),
			'committed_code_lineage_count' => $this->outsideCount(
				'SELECT COUNT(*) AS aggregate_count FROM ' . AtomicLifecycleSchema::FAMILIES . ' WHERE code_id = ?',
				array( self::PRIMARY_CODE )
			),
			'valid_code_descendant_count'  => $this->outsideCount(
				'SELECT '
				. '(SELECT COUNT(*) FROM ' . AtomicLifecycleSchema::FAMILIES . ' WHERE code_id = ? AND state = ?) '
				. '+ (SELECT COUNT(*) FROM ' . AtomicLifecycleSchema::MEMBERS . ' AS members '
				. 'INNER JOIN ' . AtomicLifecycleSchema::FAMILIES . ' AS families ON families.family_id = members.family_id '
				. 'WHERE families.code_id = ? AND members.state = ?) '
				. '+ (SELECT COUNT(*) FROM ' . AtomicLifecycleSchema::ACCESS . ' WHERE state = ? AND '
				. '(code_id = ? OR family_id IN (SELECT family_id FROM ' . AtomicLifecycleSchema::FAMILIES . ' WHERE code_id = ?))) '
				. 'AS aggregate_count',
				array( self::PRIMARY_CODE, 'active', self::PRIMARY_CODE, 'current', 'active', self::PRIMARY_CODE, self::PRIMARY_CODE )
			),
			'active_access_count'          => $this->outsideCount(
				'SELECT COUNT(*) AS aggregate_count FROM ' . AtomicLifecycleSchema::ACCESS . ' WHERE grant_id = ? AND state = ?',
				array( self::PRIMARY_GRANT, 'active' )
			),
			'current_refresh_count'        => $this->outsideCount(
				'SELECT COUNT(*) AS aggregate_count FROM ' . AtomicLifecycleSchema::MEMBERS . ' WHERE family_id = ? AND state = ?',
				array( self::PRIMARY_FAMILY, 'current' )
			),
			'code_replay_event_count'      => $this->outsideCount(
				'SELECT COUNT(*) AS aggregate_count FROM ' . AtomicLifecycleSchema::EVENTS . ' WHERE event_type = ? AND source_id = ?',
				array( 'code_replay', self::PRIMARY_CODE )
			),
			'refresh_replay_event_count'   => $this->outsideCount(
				'SELECT COUNT(*) AS aggregate_count FROM ' . AtomicLifecycleSchema::EVENTS . ' WHERE event_type = ? AND source_id = ?',
				array( 'refresh_replay', self::PRIMARY_FAMILY )
			),
			'bindings'                     => array(
				'issuer'                => self::rowString( $grant, 'issuer' ),
				'resource'              => self::rowString( $grant, 'resource_id' ),
				'client'                => self::rowString( $grant, 'client_id' ),
				'user'                  => self::rowInt( $grant, 'user_id' ),
				'scope'                 => self::rowString( $grant, 'scope_value' ),
				'inactivity_expires_at' => null !== $family
					? self::rowInt( $family, 'inactivity_expires_at' )
					: self::rowInt( $grant, 'inactivity_expires_at' ),
				'absolute_expires_at'   => null !== $family
					? self::rowInt( $family, 'absolute_expires_at' )
					: self::rowInt( $grant, 'absolute_expires_at' ),
			),
			'unrelated_state'              => $this->unrelatedState(),
		);

		try {
			// phpcs:ignore WordPress.WP.AlternativeFunctions.json_encode_json_encode -- This pure PHP fixture runs without WordPress loaded.
			$encodedState = json_encode( $state, JSON_THROW_ON_ERROR );
		} catch ( JsonException ) {
			throw new RuntimeException( 'atomic_lifecycle_snapshot_encoding_failed' );
		}

		return new AtomicLifecycleSnapshot( $state, hash( 'sha256', $encodedState ) );
	}

	/**
	 * Returns the same fixed-schema projection without its comparison fingerprint.
	 *
	 * @return array<string, int|string|bool|array<string, int|string|bool>>
	 */
	public function sanitizedEvidence(): array {
		return $this->snapshot()->sanitized();
	}

	/**
	 * Applies the complete idempotent consumed-code replay cascade.
	 *
	 * @param TransactionOwnedConnection $transaction Active transaction owner.
	 * @param TransitionControl|null     $control Coordinator and fault control.
	 */
	private function revokeCodeDescendants(
		TransactionOwnedConnection $transaction,
		?TransitionControl $control
	): void {
		$transaction->execute(
			'UPDATE ' . AtomicLifecycleSchema::CODES . ' SET state = ?, replay_event_count = 1 WHERE code_id = ? AND state <> ?',
			array( 'replay', self::PRIMARY_CODE, 'replay' )
		);
		$transaction->execute(
			'INSERT IGNORE INTO ' . AtomicLifecycleSchema::EVENTS . ' (event_key, event_type, source_id) VALUES (?, ?, ?)',
			array( 'code-replay:primary-code', 'code_replay', self::PRIMARY_CODE )
		);
		$transaction->rows(
			'SELECT family_id FROM ' . AtomicLifecycleSchema::FAMILIES . ' WHERE code_id = ? ORDER BY family_id FOR UPDATE',
			array( self::PRIMARY_CODE )
		);
		$transaction->execute(
			'UPDATE ' . AtomicLifecycleSchema::FAMILIES . ' SET state = ? WHERE code_id = ?',
			array( 'revoked', self::PRIMARY_CODE )
		);
		$this->checkpoint( $control, AtomicLifecycleCheckpoints::DURING_REVOKE, $transaction );
		$transaction->rows(
			'SELECT member_id FROM ' . AtomicLifecycleSchema::MEMBERS . ' WHERE family_id = ? ORDER BY generation FOR UPDATE',
			array( self::PRIMARY_FAMILY )
		);
		$transaction->execute(
			'UPDATE ' . AtomicLifecycleSchema::MEMBERS . ' SET state = ? WHERE family_id = ?',
			array( 'revoked', self::PRIMARY_FAMILY )
		);
		$transaction->rows(
			'SELECT access_id FROM ' . AtomicLifecycleSchema::ACCESS . ' WHERE code_id = ? OR family_id = ? ORDER BY access_id FOR UPDATE',
			array( self::PRIMARY_CODE, self::PRIMARY_FAMILY )
		);
		$transaction->execute(
			'UPDATE ' . AtomicLifecycleSchema::ACCESS . ' SET state = ? WHERE code_id = ? OR family_id = ?',
			array( 'revoked', self::PRIMARY_CODE, self::PRIMARY_FAMILY )
		);
	}

	/**
	 * Applies the complete idempotent retired-refresh replay cascade.
	 *
	 * @param TransactionOwnedConnection $transaction Active transaction owner.
	 * @param TransitionControl|null     $control Coordinator and fault control.
	 */
	private function revokeRefreshFamily(
		TransactionOwnedConnection $transaction,
		?TransitionControl $control
	): void {
		$transaction->execute(
			'UPDATE ' . AtomicLifecycleSchema::FAMILIES . ' SET state = ? WHERE family_id = ?',
			array( 'compromised', self::PRIMARY_FAMILY )
		);
		$transaction->execute(
			'UPDATE ' . AtomicLifecycleSchema::GRANTS . ' SET state = ? WHERE grant_id = ?',
			array( 'revoked', self::PRIMARY_GRANT )
		);
		$transaction->execute(
			'INSERT IGNORE INTO ' . AtomicLifecycleSchema::EVENTS . ' (event_key, event_type, source_id) VALUES (?, ?, ?)',
			array( 'refresh-replay:primary-family', 'refresh_replay', self::PRIMARY_FAMILY )
		);
		$this->checkpoint( $control, AtomicLifecycleCheckpoints::DURING_REVOKE, $transaction );
		$transaction->rows(
			'SELECT member_id FROM ' . AtomicLifecycleSchema::MEMBERS . ' WHERE family_id = ? ORDER BY generation FOR UPDATE',
			array( self::PRIMARY_FAMILY )
		);
		$transaction->execute(
			'UPDATE ' . AtomicLifecycleSchema::MEMBERS . ' SET state = ? WHERE family_id = ?',
			array( 'revoked', self::PRIMARY_FAMILY )
		);
		$transaction->rows(
			'SELECT access_id FROM ' . AtomicLifecycleSchema::ACCESS . ' WHERE grant_id = ? ORDER BY access_id FOR UPDATE',
			array( self::PRIMARY_GRANT )
		);
		$transaction->execute(
			'UPDATE ' . AtomicLifecycleSchema::ACCESS . ' SET state = ? WHERE grant_id = ?',
			array( 'revoked', self::PRIMARY_GRANT )
		);
	}

	/**
	 * Inserts the fixed primary grant.
	 *
	 * @param TransactionOwnedConnection $transaction Active transaction owner.
	 */
	private function insertPrimaryGrant( TransactionOwnedConnection $transaction ): void {
		$this->insertGrant(
			$transaction,
			self::PRIMARY_GRANT,
			self::PRIMARY_ISSUER,
			self::PRIMARY_RESOURCE,
			self::PRIMARY_CLIENT,
			self::PRIMARY_USER,
			self::PRIMARY_SCOPE,
			self::PRIMARY_INACTIVITY_EXPIRY,
			self::PRIMARY_ABSOLUTE_EXPIRY
		);
	}

	/**
	 * Inserts a complete unrelated credential domain.
	 *
	 * @param TransactionOwnedConnection $transaction Active transaction owner.
	 */
	private function insertUnrelatedDomain( TransactionOwnedConnection $transaction ): void {
		$this->insertGrant(
			$transaction,
			self::UNRELATED_GRANT,
			self::UNRELATED_ISSUER,
			self::UNRELATED_RESOURCE,
			self::UNRELATED_CLIENT,
			self::UNRELATED_USER,
			self::UNRELATED_SCOPE,
			self::UNRELATED_INACTIVITY_EXPIRY,
			self::UNRELATED_ABSOLUTE_EXPIRY
		);
		$this->insertFamily(
			$transaction,
			self::UNRELATED_FAMILY,
			self::UNRELATED_GRANT,
			null,
			self::UNRELATED_INACTIVITY_EXPIRY,
			self::UNRELATED_ABSOLUTE_EXPIRY
		);
		$this->insertRefreshMember( $transaction, self::UNRELATED_FAMILY, 0, null, 'current' );
		$this->insertAccess( $transaction, self::UNRELATED_GRANT, null, self::UNRELATED_FAMILY, 0, 'unrelated-access' );
	}

	/**
	 * Inserts one proof grant with exact public bindings.
	 *
	 * @param TransactionOwnedConnection $transaction Active transaction owner.
	 * @param string                     $grantId Non-secret grant locator.
	 * @param string                     $issuer Exact issuer identifier.
	 * @param string                     $resourceIdentifier Exact resource identifier.
	 * @param string                     $client Exact client identifier.
	 * @param int                        $user Exact user locator.
	 * @param string                     $scope Exact scope set.
	 * @param int                        $inactivityExpiry Fixed inactivity expiry.
	 * @param int                        $absoluteExpiry Fixed absolute expiry.
	 */
	private function insertGrant(
		TransactionOwnedConnection $transaction,
		string $grantId,
		string $issuer,
		string $resourceIdentifier,
		string $client,
		int $user,
		string $scope,
		int $inactivityExpiry,
		int $absoluteExpiry
	): void {
		$transaction->execute(
			'INSERT INTO ' . AtomicLifecycleSchema::GRANTS . ' (grant_id, issuer, resource_id, client_id, user_id, scope_value, state, inactivity_expires_at, absolute_expires_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)',
			array( $grantId, $issuer, $resourceIdentifier, $client, $user, $scope, 'active', $inactivityExpiry, $absoluteExpiry )
		);
	}

	/**
	 * Inserts one refresh-family aggregate.
	 *
	 * @param TransactionOwnedConnection $transaction Active transaction owner.
	 * @param string                     $familyId Non-secret family locator.
	 * @param string                     $grantId Owning grant locator.
	 * @param string|null                $codeId Issuing code locator, when present.
	 * @param int                        $inactivityExpiry Fixed inactivity expiry.
	 * @param int                        $absoluteExpiry Fixed absolute expiry.
	 */
	private function insertFamily(
		TransactionOwnedConnection $transaction,
		string $familyId,
		string $grantId,
		?string $codeId,
		int $inactivityExpiry,
		int $absoluteExpiry
	): void {
		$transaction->execute(
			'INSERT INTO ' . AtomicLifecycleSchema::FAMILIES . ' (family_id, grant_id, code_id, state, current_generation, inactivity_expires_at, absolute_expires_at) VALUES (?, ?, ?, ?, 0, ?, ?)',
			array( $familyId, $grantId, $codeId, 'active', $inactivityExpiry, $absoluteExpiry )
		);
	}

	/**
	 * Inserts one digested refresh member.
	 *
	 * @param TransactionOwnedConnection $transaction Active transaction owner.
	 * @param string                     $familyId Owning family locator.
	 * @param int                        $generation Fixed generation.
	 * @param string|null                $parentDigest Parent proof digest.
	 * @param string                     $state Fixed lifecycle state.
	 */
	private function insertRefreshMember(
		TransactionOwnedConnection $transaction,
		string $familyId,
		int $generation,
		?string $parentDigest,
		string $state
	): void {
		$transaction->execute(
			'INSERT INTO ' . AtomicLifecycleSchema::MEMBERS . ' (member_digest, member_id, family_id, generation, parent_digest, state) VALUES (?, ?, ?, ?, ?, ?)',
			array(
				self::randomProofDigest(),
				$familyId . '-member-' . $generation,
				$familyId,
				$generation,
				$parentDigest,
				$state,
			)
		);
	}

	/**
	 * Inserts one digested access descendant.
	 *
	 * @param TransactionOwnedConnection $transaction Active transaction owner.
	 * @param string                     $grantId Owning grant locator.
	 * @param string|null                $codeId Issuing code locator.
	 * @param string|null                $familyId Owning family locator.
	 * @param int|null                   $generation Issuing refresh generation.
	 * @param string                     $issuanceKey Non-secret uniqueness locator.
	 */
	private function insertAccess(
		TransactionOwnedConnection $transaction,
		string $grantId,
		?string $codeId,
		?string $familyId,
		?int $generation,
		string $issuanceKey
	): void {
		$transaction->execute(
			'INSERT INTO ' . AtomicLifecycleSchema::ACCESS . ' (access_digest, access_id, issuance_key, grant_id, code_id, family_id, generation, state) VALUES (?, ?, ?, ?, ?, ?, ?, ?)',
			array(
				self::randomProofDigest(),
				$issuanceKey,
				$issuanceKey,
				$grantId,
				$codeId,
				$familyId,
				$generation,
				'active',
			)
		);
	}

	/**
	 * Inserts the two harmless error-recovery sentinels.
	 *
	 * @param TransactionOwnedConnection $transaction Active transaction owner.
	 */
	private function insertSentinels( TransactionOwnedConnection $transaction ): void {
		$transaction->execute(
			'INSERT INTO ' . AtomicLifecycleSchema::SENTINELS . ' (sentinel_id, value_number) VALUES (1, 0), (2, 0)'
		);
	}

	/**
	 * Locks one grant aggregate before any descendant lock.
	 *
	 * @param TransactionOwnedConnection $transaction Active transaction owner.
	 * @param string                     $grantId Exact grant locator.
	 * @throws RuntimeException When the grant aggregate is absent.
	 */
	private function lockGrant( TransactionOwnedConnection $transaction, string $grantId ): void {
		$row = $transaction->row(
			'SELECT state FROM ' . AtomicLifecycleSchema::GRANTS . ' WHERE grant_id = ? FOR UPDATE',
			array( $grantId )
		);

		if ( null === $row ) {
			throw new RuntimeException( 'atomic_lifecycle_missing_grant' );
		}
	}

	/**
	 * Emits one deterministic checkpoint.
	 *
	 * @param TransitionControl|null     $control Coordinator and fault control.
	 * @param string                     $checkpoint Fixed checkpoint name.
	 * @param TransactionOwnedConnection $transaction Active transaction owner.
	 */
	private function checkpoint(
		?TransitionControl $control,
		string $checkpoint,
		TransactionOwnedConnection $transaction
	): void {
		$control?->reach( $checkpoint, $transaction->transactionConnectionId() );
	}

	/**
	 * Returns the unrelated domain's complete sanitized semantic state.
	 *
	 * @return array<string, int|string|bool>
	 */
	private function unrelatedState(): array {
		$grant  = $this->outsideRow(
			'SELECT issuer, resource_id, client_id, user_id, scope_value, state, inactivity_expires_at, absolute_expires_at FROM ' . AtomicLifecycleSchema::GRANTS . ' WHERE grant_id = ?',
			array( self::UNRELATED_GRANT )
		);
		$family = $this->outsideRow(
			'SELECT state, current_generation FROM ' . AtomicLifecycleSchema::FAMILIES . ' WHERE family_id = ?',
			array( self::UNRELATED_FAMILY )
		);

		return array(
			'grant_state'           => self::rowString( $grant, 'state', 'absent' ),
			'family_state'          => self::rowString( $family, 'state', 'absent' ),
			'current_generation'    => self::rowInt( $family, 'current_generation', -1 ),
			'active_access_count'   => $this->outsideCount(
				'SELECT COUNT(*) AS aggregate_count FROM ' . AtomicLifecycleSchema::ACCESS . ' WHERE grant_id = ? AND state = ?',
				array( self::UNRELATED_GRANT, 'active' )
			),
			'current_refresh_count' => $this->outsideCount(
				'SELECT COUNT(*) AS aggregate_count FROM ' . AtomicLifecycleSchema::MEMBERS . ' WHERE family_id = ? AND state = ?',
				array( self::UNRELATED_FAMILY, 'current' )
			),
			'issuer'                => self::rowString( $grant, 'issuer' ),
			'resource'              => self::rowString( $grant, 'resource_id' ),
			'client'                => self::rowString( $grant, 'client_id' ),
			'user'                  => self::rowInt( $grant, 'user_id' ),
			'scope'                 => self::rowString( $grant, 'scope_value' ),
			'inactivity_expires_at' => self::rowInt( $grant, 'inactivity_expires_at' ),
			'absolute_expires_at'   => self::rowInt( $grant, 'absolute_expires_at' ),
		);
	}

	/**
	 * Generates one disposable digest from random raw material retained only
	 * for the duration of this call.
	 */
	private static function randomProofDigest(): string {
		$rawMaterial = random_bytes( 32 );

		try {
			return hash( 'sha256', $rawMaterial );
		} finally {
			if ( function_exists( 'sodium_memzero' ) ) {
				sodium_memzero( $rawMaterial );
			}
		}
	}

	/**
	 * Executes one fixture statement outside a behavioral transaction.
	 *
	 * @param string                      $sql Fixed proof SQL.
	 * @param list<int|float|string|null> $parameters Bound values.
	 * @throws RuntimeException When the statement fails.
	 */
	private function outsideExecute( string $sql, array $parameters = array() ): int {
		$result = $this->database->execute_query( $sql, $parameters );

		if ( false === $result ) {
			throw new RuntimeException( 'atomic_lifecycle_fixture_query_failed' );
		}

		if ( $result instanceof mysqli_result ) {
			$result->free();
		}

		$affectedRows = $this->database->affected_rows;

		return is_int( $affectedRows ) ? $affectedRows : (int) $affectedRows;
	}

	/**
	 * Reads one fixture row outside a behavioral transaction.
	 *
	 * @param string                      $sql Fixed proof SQL.
	 * @param list<int|float|string|null> $parameters Bound values.
	 * @return array<string, mixed>|null
	 */
	private function outsideRow( string $sql, array $parameters = array() ): ?array {
		$rows = $this->outsideRows( $sql, $parameters );

		return $rows[0] ?? null;
	}

	/**
	 * Reads fixture rows outside a behavioral transaction.
	 *
	 * @param string                      $sql Fixed proof SQL.
	 * @param list<int|float|string|null> $parameters Bound values.
	 * @return list<array<string, mixed>>
	 * @throws RuntimeException When the read fails.
	 */
	private function outsideRows( string $sql, array $parameters = array() ): array {
		$result = $this->database->execute_query( $sql, $parameters );

		if ( ! $result instanceof mysqli_result ) {
			throw new RuntimeException( 'atomic_lifecycle_fixture_read_failed' );
		}

		$rows = array();

		$row = $result->fetch_assoc();

		while ( is_array( $row ) ) {
			$rows[] = $row;
			$row    = $result->fetch_assoc();
		}

		$result->free();

		return $rows;
	}

	/**
	 * Reads one fixture count outside a behavioral transaction.
	 *
	 * @param string                      $sql Fixed count SQL.
	 * @param list<int|float|string|null> $parameters Bound values.
	 */
	private function outsideCount( string $sql, array $parameters = array() ): int {
		$row = $this->outsideRow( $sql, $parameters );

		return self::rowInt( $row, 'aggregate_count' );
	}

	/**
	 * Returns one required string database value.
	 *
	 * @param array<string, mixed>|null $row Database row.
	 * @param string                    $key Fixed field name.
	 * @param string                    $fallback Value used when the row or field is absent.
	 * @throws RuntimeException When a present value is not a string.
	 */
	private static function rowString( ?array $row, string $key, string $fallback = '' ): string {
		$value = $row[ $key ] ?? null;

		if ( null === $value ) {
			return $fallback;
		}

		if ( ! is_string( $value ) ) {
			throw new RuntimeException( 'atomic_lifecycle_invalid_string_field' );
		}

		return $value;
	}

	/**
	 * Returns one required integer database value.
	 *
	 * @param array<string, mixed>|null $row Database row.
	 * @param string                    $key Fixed field name.
	 * @param int                       $fallback Value used when the row or field is absent.
	 * @throws RuntimeException When a present value is not numeric.
	 */
	private static function rowInt( ?array $row, string $key, int $fallback = 0 ): int {
		$value = $row[ $key ] ?? null;

		if ( null === $value ) {
			return $fallback;
		}

		if ( ! is_numeric( $value ) ) {
			throw new RuntimeException( 'atomic_lifecycle_invalid_integer_field' );
		}

		return (int) $value;
	}
}
