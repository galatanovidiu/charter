<?php
/**
 * Deterministic scenario coordinator for the disposable Slice 0 P1 proof.
 *
 * @package GalatanOvidiu\Charter
 */

declare(strict_types=1);

namespace GalatanOvidiu\Charter\Tests\Fixtures\AtomicLifecycle;

// phpcs:disable Generic.Commenting.DocComment.MissingShort, Squiz.Commenting -- The large scenario coordinator documents its public contract and keeps private orchestration compact.

require_once dirname( __DIR__, 3 ) . '/vendor/autoload.php';
require_once __DIR__ . '/HarnessContract.php';
require_once __DIR__ . '/LaneConfiguration.php';
require_once __DIR__ . '/SanitizedResult.php';
require_once __DIR__ . '/WorkerProcess.php';

use GalatanOvidiu\Charter\Tests\Prototype\AtomicLifecycle\AtomicLifecycleCheckpoints;
use GalatanOvidiu\Charter\Tests\Prototype\AtomicLifecycle\AtomicLifecycleSchema;
use GalatanOvidiu\Charter\Tests\Prototype\AtomicLifecycle\AtomicLifecycleSnapshot;
use GalatanOvidiu\Charter\Tests\Prototype\AtomicLifecycle\AtomicLifecycleStore;
use GalatanOvidiu\Charter\Tests\Prototype\AtomicLifecycle\TransitionControl;
use GalatanOvidiu\Charter\Tests\Prototype\AtomicLifecycle\TransitionFailure;
use mysqli_result;
use RuntimeException;
use Throwable;

/**
 * Runs one case at a time against an already-created disposable fixture.
 */
final class AtomicLifecycleHarness {

	/**
	 * Creates only the exact provisional P1 tables.
	 */
	public static function createFixture( ?LaneConfiguration $lane = null ): void {
		$configuration = $lane ?? LaneConfiguration::fromEnvironment();
		$database      = $configuration->connect();

		try {
			AtomicLifecycleSchema::drop( $database );
			AtomicLifecycleSchema::create( $database );
		} finally {
			$database->close();
		}
	}

	/**
	 * Drops only the exact provisional P1 tables.
	 */
	public static function dropFixture( ?LaneConfiguration $lane = null ): void {
		$configuration = $lane ?? LaneConfiguration::fromEnvironment();
		$database      = $configuration->connect();

		try {
			AtomicLifecycleSchema::drop( $database );
		} finally {
			$database->close();
		}
	}

	/**
	 * Counts only exact P1 tables after cleanup.
	 */
	public static function cleanupTablesRemaining( ?LaneConfiguration $lane = null ): int {
		$configuration = $lane ?? LaneConfiguration::fromEnvironment();
		$database      = $configuration->connect();

		try {
			$placeholders = implode( ', ', array_fill( 0, count( AtomicLifecycleSchema::tableNames() ), '?' ) );
			$result       = $database->execute_query(
				"SELECT COUNT(*) AS table_count FROM information_schema.TABLES WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME IN ({$placeholders})",
				AtomicLifecycleSchema::tableNames()
			);
			$row          = $result instanceof mysqli_result ? $result->fetch_assoc() : null;

			if ( $result instanceof mysqli_result ) {
				$result->free();
			}

			return is_array( $row ) ? (int) $row['table_count'] : count( AtomicLifecycleSchema::tableNames() );
		} finally {
			$database->close();
		}
	}

	/**
	 * Runs one canonical case with an injected or current lane.
	 *
	 * @return array<string, mixed>
	 */
	public static function runCase(
		string $caseId,
		?LaneConfiguration $lane = null,
		?int $workers = null,
		?int $rounds = null
	): array {
		$configuration = $lane ?? LaneConfiguration::fromEnvironment();
		$workerCount   = $workers ?? HarnessContract::DEFAULT_WORKERS;
		$roundCount    = $rounds ?? HarnessContract::DEFAULT_ROUNDS;
		$result        = SanitizedResult::base( $configuration, $caseId, $workerCount, $roundCount );

		if (
			! in_array( $caseId, HarnessContract::cases(), true )
			|| 1 > $workerCount
			|| HarnessContract::MAXIMUM_WORKERS < $workerCount
			|| 1 > $roundCount
			|| HarnessContract::MAXIMUM_ROUNDS < $roundCount
		) {
			return $result;
		}

		try {
			$caseResult = match ( $caseId ) {
				HarnessContract::CASE_PREFLIGHT => self::runPreflight( $configuration, $workerCount ),
				HarnessContract::CASE_CODE_EXCHANGE => self::runCodeExchange( $configuration ),
				HarnessContract::CASE_CODE_RACE => self::runRace(
					$configuration,
					HarnessContract::CASE_CODE_RACE,
					HarnessContract::ACTION_EXCHANGE_CODE,
					$workerCount,
					$roundCount
				),
				HarnessContract::CASE_CODE_REPLAY => self::runCodeReplay( $configuration ),
				HarnessContract::CASE_CODE_WORKER_DEATH => self::runCodeWorkerDeath( $configuration ),
				HarnessContract::CASE_CODE_COMMIT_AMBIGUITY => self::runCommitAmbiguity( $configuration ),
				HarnessContract::CASE_REFRESH_ROTATION => self::runRefreshRotation( $configuration ),
				HarnessContract::CASE_REFRESH_RACE => self::runRace(
					$configuration,
					HarnessContract::CASE_REFRESH_RACE,
					HarnessContract::ACTION_ROTATE_REFRESH,
					$workerCount,
					$roundCount
				),
				HarnessContract::CASE_REFRESH_ANCESTOR_REPLAY => self::runRefreshAncestorReplay( $configuration ),
				HarnessContract::CASE_DEADLOCK => self::runDeadlock( $configuration ),
				HarnessContract::CASE_LOCK_TIMEOUT => self::runLockTimeout( $configuration ),
				HarnessContract::CASE_CONNECTION_LOSS => self::runConnectionLoss( $configuration ),
			};
			$remaining                                = WorkerProcess::activeCount();
			$caseResult['worker_processes_remaining'] = $remaining;

			if ( 0 !== $remaining ) {
				$caseResult['status'] = HarnessContract::OUTCOME_FAILED;
				$caseResult['passed'] = false;
			}

			return SanitizedResult::validate( $caseResult ) ? $caseResult : $result;
		} catch ( Throwable ) {
			return $result;
		}
	}

	/**
	 * @return array<string, mixed>
	 */
	private static function runPreflight( LaneConfiguration $lane, int $workerCount ): array {
		$result       = SanitizedResult::base( $lane, HarnessContract::CASE_PREFLIGHT, $workerCount, 1 );
		$database     = $lane->connect();
		$store        = new AtomicLifecycleStore( $database );
		$capabilities = AtomicLifecycleSchema::capabilities( $database );
		$workers      = self::startWorkers( $workerCount );
		$ids          = array_map( static fn( WorkerProcess $worker ): int => $worker->connectionId(), $workers );

		try {
			foreach ( $workers as $worker ) {
				$worker->send( array( 'command' => HarnessContract::COMMAND_STOP ) );
			}

			self::seedScenario( HarnessContract::ACTION_SEED_CODE );
			$before     = $store->sentinelValues();
			$rolledBack = false;
			try {
				$store->exerciseSentinelTransition(
					1,
					2,
					new TransitionControl( null, array( AtomicLifecycleCheckpoints::AFTER_FIRST_SENTINEL_LOCK ) )
				);
			} catch ( TransitionFailure $failure ) {
				$rolledBack = TransitionFailure::INJECTED === $failure->classification();
			}

			$serverVersionOk = self::serverVersionMatches( $database, $lane );
			$isolationOk     = self::isolationMatches( $database, $lane );
			$snapshotOk      = self::snapshotIsolationMatches( $database, $lane );
			$readWrite       = self::serverIsReadWrite( $database );
			$galera          = self::galeraEnabled( $database, $lane );
			$sqlMode         = self::serverSqlMode( $database );
			$passed          = $capabilities['tables_present']
				&& $capabilities['all_innodb']
				&& $capabilities['unique_invariants_present']
				&& count( array_unique( $ids ) ) === $workerCount
				&& $rolledBack
				&& $before === $store->sentinelValues()
				&& $serverVersionOk
				&& $isolationOk
				&& $snapshotOk
				&& $readWrite
				&& '' !== $sqlMode
				&& ! $galera;

			return self::complete(
				$result,
				array(
					'distinct_connections' => count( array_unique( $ids ) ),
					'rollbacks'            => $rolledBack ? 1 : 0,
					'constraints_enforced' => $capabilities['unique_invariants_present'],
					'autocommit_initial'   => self::autocommitIsOn( $database ),
					'read_write'           => $readWrite,
					'sql_mode'             => $sqlMode,
					'proxied'              => false,
					'replicated'           => false,
					'galera'               => $galera,
					'outcomes'             => array( $rolledBack ? HarnessContract::OUTCOME_ROLLED_BACK : HarnessContract::OUTCOME_FAILED ),
				),
				$passed
			);
		} finally {
			self::closeWorkers( $workers );
			$database->close();
		}
	}

	/**
	 * @return array<string, mixed>
	 */
	private static function runCodeExchange( LaneConfiguration $lane ): array {
		$result   = SanitizedResult::base( $lane, HarnessContract::CASE_CODE_EXCHANGE, 1, 1 );
		$database = $lane->connect();
		$store    = new AtomicLifecycleStore( $database );

		try {
			self::seedScenario( HarnessContract::ACTION_SEED_CODE );
			$before   = $store->snapshot();
			$response = self::runSingleAction( self::command( HarnessContract::ACTION_EXCHANGE_CODE ) );
			$after    = $store->snapshot();
			$passed   = HarnessContract::OUTCOME_WINNER === $response['outcome']
				&& true === $response['committed']
				&& 'consumed' === $after->codeState()
				&& 1 === $after->committedCodeLineageCount()
				&& 1 === $after->activeAccessCount()
				&& 1 === $after->currentRefreshCount()
				&& self::preservedDomain( $before, $after );

			return self::complete(
				$result,
				self::snapshotFields( $after ) + array(
					'responses_successful'      => 1,
					'committed_winners'         => 1,
					'distinct_connections'      => 1,
					'unrelated_state_unchanged' => self::unrelatedUnchanged( $before, $after ),
					'sibling_domain_unchanged'  => self::unrelatedUnchanged( $before, $after ),
					'outcomes'                  => array( HarnessContract::OUTCOME_WINNER ),
				),
				$passed
			);
		} finally {
			$database->close();
		}
	}

	/**
	 * @return array<string, mixed>
	 */
	private static function runRace(
		LaneConfiguration $lane,
		string $caseId,
		string $action,
		int $workerCount,
		int $roundCount
	): array {
		$result             = SanitizedResult::base( $lane, $caseId, $workerCount, $roundCount );
		$database           = $lane->connect();
		$store              = new AtomicLifecycleStore( $database );
		$successful         = 0;
		$winners            = 0;
		$replays            = 0;
		$replayEvents       = 0;
		$allConnections     = true;
		$allTerminal        = true;
		$unrelatedUnchanged = true;
		$lastSnapshot       = null;

		try {
			for ( $round = 0; $round < $roundCount; ++$round ) {
				if ( HarnessContract::ACTION_EXCHANGE_CODE === $action ) {
					self::seedScenario( HarnessContract::ACTION_SEED_CODE );
				} else {
					self::seedScenario( HarnessContract::ACTION_SEED_REFRESH );
				}

				$before  = $store->snapshot();
				$workers = self::startWorkers( $workerCount );
				$ids     = array_map( static fn( WorkerProcess $worker ): int => $worker->connectionId(), $workers );

				try {
					$generation = HarnessContract::ACTION_ROTATE_REFRESH === $action ? 0 : null;
					$workers[0]->send(
						self::command( $action, array( AtomicLifecycleCheckpoints::AFTER_AGGREGATE_LOCK ), array(), null, $generation )
					);
					$workers[0]->waitForType( HarnessContract::MESSAGE_CHECKPOINT, AtomicLifecycleCheckpoints::AFTER_AGGREGATE_LOCK );

					for ( $index = 1; $index < $workerCount; ++$index ) {
						$workers[ $index ]->send(
							self::command( $action, array( AtomicLifecycleCheckpoints::BEFORE_CLAIM ), array(), null, $generation )
						);
					}

					for ( $index = 1; $index < $workerCount; ++$index ) {
						$workers[ $index ]->waitForType( HarnessContract::MESSAGE_CHECKPOINT, AtomicLifecycleCheckpoints::BEFORE_CLAIM );
					}

					for ( $index = 1; $index < $workerCount; ++$index ) {
						$workers[ $index ]->release( AtomicLifecycleCheckpoints::BEFORE_CLAIM );
					}
					$workers[0]->release( AtomicLifecycleCheckpoints::AFTER_AGGREGATE_LOCK );

					$responses = array();
					foreach ( $workers as $worker ) {
						$responses[] = $worker->waitForType( HarnessContract::MESSAGE_RESULT );
					}
				} finally {
					self::closeWorkers( $workers );
				}

				$roundWinners = self::outcomeCount( $responses, HarnessContract::OUTCOME_WINNER );
				$roundReplays = self::outcomeCount( $responses, HarnessContract::OUTCOME_REPLAY );
				$after        = $store->snapshot();
				$eventCount   = HarnessContract::ACTION_EXCHANGE_CODE === $action
					? $after->codeReplayEventCount()
					: $after->refreshReplayEventCount();
				$terminal     = 1 === $roundWinners
					&& $workerCount - 1 === $roundReplays
					&& 0 === $after->activeAccessCount()
					&& 0 === $after->currentRefreshCount()
					&& 1 === $eventCount;

				$successful        += $roundWinners;
				$winners           += $roundWinners;
				$replays           += $roundReplays;
				$replayEvents      += $eventCount;
				$allConnections     = $allConnections && count( array_unique( $ids ) ) === $workerCount;
				$allTerminal        = $allTerminal && $terminal;
				$unrelatedUnchanged = $unrelatedUnchanged && self::preservedDomain( $before, $after );
				$lastSnapshot       = $after;
			}

			if ( ! $lastSnapshot instanceof AtomicLifecycleSnapshot ) {
				throw new RuntimeException( 'Race produced no authoritative snapshot.' );
			}

			$passed = $allConnections && $allTerminal && $unrelatedUnchanged;

			return self::complete(
				$result,
				self::snapshotFields( $lastSnapshot ) + array(
					'responses_successful'      => $successful,
					'committed_winners'         => $winners,
					'replays'                   => $replays,
					'replay_events'             => $replayEvents,
					'distinct_connections'      => $allConnections ? $workerCount : 0,
					'unrelated_state_unchanged' => $unrelatedUnchanged,
					'sibling_domain_unchanged'  => $unrelatedUnchanged,
					'outcomes'                  => array( HarnessContract::OUTCOME_WINNER, HarnessContract::OUTCOME_REPLAY ),
				),
				$passed
			);
		} finally {
			$database->close();
		}
	}

	/**
	 * @return array<string, mixed>
	 */
	private static function runCodeReplay( LaneConfiguration $lane ): array {
		$result   = SanitizedResult::base( $lane, HarnessContract::CASE_CODE_REPLAY, 1, 1 );
		$database = $lane->connect();
		$store    = new AtomicLifecycleStore( $database );

		try {
			self::seedScenario( HarnessContract::ACTION_SEED_CODE );
			$before   = $store->snapshot();
			$winner   = self::runSingleAction( self::command( HarnessContract::ACTION_EXCHANGE_CODE ) );
			$rotation = self::runSingleAction(
				self::command( HarnessContract::ACTION_ROTATE_REFRESH, array(), array(), null, 0 )
			);
			$rotated  = $store->snapshot();
			$replay   = self::runSingleAction( self::command( HarnessContract::ACTION_EXCHANGE_CODE ) );
			$repeat   = self::runSingleAction( self::command( HarnessContract::ACTION_EXCHANGE_CODE ) );
			$invalid  = self::runSingleAction( self::command( HarnessContract::ACTION_EXCHANGE_UNKNOWN_CODE ) );
			$after    = $store->snapshot();
			$passed   = HarnessContract::OUTCOME_WINNER === $winner['outcome']
				&& HarnessContract::OUTCOME_WINNER === $rotation['outcome']
				&& 4 === $rotated->validCodeDescendantCount()
				&& HarnessContract::OUTCOME_REPLAY === $replay['outcome']
				&& HarnessContract::OUTCOME_REPLAY === $repeat['outcome']
				&& HarnessContract::OUTCOME_INVALID === $invalid['outcome']
				&& 0 === $after->activeAccessCount()
				&& 0 === $after->currentRefreshCount()
				&& 1 === $after->codeReplayEventCount()
				&& self::preservedDomain( $before, $after );

			return self::complete(
				$result,
				self::snapshotFields( $after ) + array(
					'responses_successful'      => 2,
					'committed_winners'         => 2,
					'replays'                   => 2,
					'replay_events'             => 1,
					'distinct_connections'      => 5,
					'unrelated_state_unchanged' => self::unrelatedUnchanged( $before, $after ),
					'sibling_domain_unchanged'  => self::unrelatedUnchanged( $before, $after ),
					'outcomes'                  => array( HarnessContract::OUTCOME_WINNER, HarnessContract::OUTCOME_REPLAY, HarnessContract::OUTCOME_INVALID ),
				),
				$passed
			);
		} finally {
			$database->close();
		}
	}

	/**
	 * @return array<string, mixed>
	 */
	private static function runCodeWorkerDeath( LaneConfiguration $lane ): array {
		$result   = SanitizedResult::base( $lane, HarnessContract::CASE_CODE_WORKER_DEATH, 1, 1 );
		$database = $lane->connect();
		$store    = new AtomicLifecycleStore( $database );

		try {
			self::seedScenario( HarnessContract::ACTION_SEED_CODE );
			$before = $store->snapshot();
			$worker = self::startWorkers( 1 )[0];
			$worker->send(
				self::command(
					HarnessContract::ACTION_EXCHANGE_CODE,
					array(),
					array(),
					AtomicLifecycleCheckpoints::BEFORE_COMMIT
				)
			);
			$worker->waitForType( HarnessContract::MESSAGE_CHECKPOINT, AtomicLifecycleCheckpoints::BEFORE_COMMIT );
			$exitCode   = $worker->close();
			$afterDeath = $store->snapshot();
			$retry      = self::runSingleAction( self::command( HarnessContract::ACTION_EXCHANGE_CODE ) );
			$after      = $store->snapshot();
			$passed     = HarnessContract::WORKER_EXIT_EXPECTED_DEATH === $exitCode
				&& $before->fingerprint() === $afterDeath->fingerprint()
				&& HarnessContract::OUTCOME_WINNER === $retry['outcome']
				&& 1 === $after->committedCodeLineageCount();

			return self::complete(
				$result,
				self::snapshotFields( $after ) + array(
					'responses_successful'      => 1,
					'committed_winners'         => 1,
					'rollbacks'                 => 1,
					'retries'                   => 1,
					'worker_deaths'             => 1,
					'distinct_connections'      => 2,
					'unrelated_state_unchanged' => self::unrelatedUnchanged( $before, $after ),
					'sibling_domain_unchanged'  => self::unrelatedUnchanged( $before, $after ),
					'outcomes'                  => array( HarnessContract::OUTCOME_WORKER_DIED, HarnessContract::OUTCOME_WINNER ),
				),
				$passed
			);
		} finally {
			$database->close();
		}
	}

	/**
	 * @return array<string, mixed>
	 */
	private static function runCommitAmbiguity( LaneConfiguration $lane ): array {
		$result   = SanitizedResult::base( $lane, HarnessContract::CASE_CODE_COMMIT_AMBIGUITY, 1, 1 );
		$database = $lane->connect();
		$store    = new AtomicLifecycleStore( $database );

		try {
			self::seedScenario( HarnessContract::ACTION_SEED_CODE );
			$before = $store->snapshot();
			$worker = self::startWorkers( 1 )[0];
			$worker->send(
				self::command(
					HarnessContract::ACTION_EXCHANGE_CODE,
					array(),
					array(),
					AtomicLifecycleCheckpoints::AFTER_COMMIT
				)
			);
			$worker->waitForType( HarnessContract::MESSAGE_CHECKPOINT, AtomicLifecycleCheckpoints::AFTER_COMMIT );
			$exitCode  = $worker->close();
			$ambiguous = $store->snapshot();
			$retry     = self::runSingleAction( self::command( HarnessContract::ACTION_EXCHANGE_CODE ) );
			$after     = $store->snapshot();
			$passed    = HarnessContract::WORKER_EXIT_EXPECTED_DEATH === $exitCode
				&& 1 === $ambiguous->committedCodeLineageCount()
				&& HarnessContract::OUTCOME_REPLAY === $retry['outcome']
				&& 0 === $after->activeAccessCount()
				&& 0 === $after->currentRefreshCount()
				&& 1 === $after->codeReplayEventCount();

			return self::complete(
				$result,
				self::snapshotFields( $after ) + array(
					'committed_winners'         => 1,
					'replays'                   => 1,
					'retries'                   => 1,
					'worker_deaths'             => 1,
					'replay_events'             => 1,
					'distinct_connections'      => 2,
					'unrelated_state_unchanged' => self::unrelatedUnchanged( $before, $after ),
					'sibling_domain_unchanged'  => self::unrelatedUnchanged( $before, $after ),
					'outcomes'                  => array( HarnessContract::OUTCOME_COMMIT_AMBIGUOUS, HarnessContract::OUTCOME_REPLAY ),
				),
				$passed
			);
		} finally {
			$database->close();
		}
	}

	/**
	 * @return array<string, mixed>
	 */
	private static function runRefreshRotation( LaneConfiguration $lane ): array {
		$result   = SanitizedResult::base( $lane, HarnessContract::CASE_REFRESH_ROTATION, 1, 1 );
		$database = $lane->connect();
		$store    = new AtomicLifecycleStore( $database );

		try {
			self::seedScenario( HarnessContract::ACTION_SEED_REFRESH );
			$before   = $store->snapshot();
			$response = self::runSingleAction( self::command( HarnessContract::ACTION_ROTATE_REFRESH, array(), array(), null, 0 ) );
			$after    = $store->snapshot();
			$passed   = HarnessContract::OUTCOME_WINNER === $response['outcome']
				&& 1 === $after->familyCurrentGeneration()
				&& 1 === $after->currentRefreshCount()
				&& 3 === $after->activeAccessCount()
				&& self::preservedDomain( $before, $after );

			return self::complete(
				$result,
				self::snapshotFields( $after ) + array(
					'responses_successful'      => 1,
					'committed_winners'         => 1,
					'distinct_connections'      => 1,
					'unrelated_state_unchanged' => self::unrelatedUnchanged( $before, $after ),
					'sibling_domain_unchanged'  => self::unrelatedUnchanged( $before, $after ),
					'outcomes'                  => array( HarnessContract::OUTCOME_WINNER ),
				),
				$passed
			);
		} finally {
			$database->close();
		}
	}

	/**
	 * @return array<string, mixed>
	 */
	private static function runRefreshAncestorReplay( LaneConfiguration $lane ): array {
		$result   = SanitizedResult::base( $lane, HarnessContract::CASE_REFRESH_ANCESTOR_REPLAY, 1, 1 );
		$database = $lane->connect();
		$store    = new AtomicLifecycleStore( $database );

		try {
			self::seedScenario( HarnessContract::ACTION_SEED_REFRESH );
			$before = $store->snapshot();
			$first  = self::runSingleAction( self::command( HarnessContract::ACTION_ROTATE_REFRESH, array(), array(), null, 0 ) );
			$second = self::runSingleAction( self::command( HarnessContract::ACTION_ROTATE_REFRESH, array(), array(), null, 1 ) );
			$replay = self::runSingleAction( self::command( HarnessContract::ACTION_ROTATE_REFRESH, array(), array(), null, 0 ) );
			$repeat = self::runSingleAction( self::command( HarnessContract::ACTION_ROTATE_REFRESH, array(), array(), null, 0 ) );
			$after  = $store->snapshot();
			$passed = HarnessContract::OUTCOME_WINNER === $first['outcome']
				&& HarnessContract::OUTCOME_WINNER === $second['outcome']
				&& HarnessContract::OUTCOME_REPLAY === $replay['outcome']
				&& HarnessContract::OUTCOME_REPLAY === $repeat['outcome']
				&& 'compromised' === $after->familyState()
				&& 'revoked' === $after->grantState()
				&& 0 === $after->activeAccessCount()
				&& 0 === $after->currentRefreshCount()
				&& 1 === $after->refreshReplayEventCount()
				&& self::preservedDomain( $before, $after );

			return self::complete(
				$result,
				self::snapshotFields( $after ) + array(
					'responses_successful'      => 2,
					'committed_winners'         => 2,
					'replays'                   => 2,
					'replay_events'             => 1,
					'distinct_connections'      => 4,
					'unrelated_state_unchanged' => self::unrelatedUnchanged( $before, $after ),
					'sibling_domain_unchanged'  => self::unrelatedUnchanged( $before, $after ),
					'outcomes'                  => array( HarnessContract::OUTCOME_WINNER, HarnessContract::OUTCOME_REPLAY ),
				),
				$passed
			);
		} finally {
			$database->close();
		}
	}

	/**
	 * @return array<string, mixed>
	 */
	private static function runDeadlock( LaneConfiguration $lane ): array {
		$result   = SanitizedResult::base( $lane, HarnessContract::CASE_DEADLOCK, 2, 1 );
		$database = $lane->connect();
		$store    = new AtomicLifecycleStore( $database );

		try {
			self::seedScenario( HarnessContract::ACTION_SEED_CODE );
			$before  = $store->snapshot();
			$workers = self::startWorkers( 2 );

			try {
				$workers[0]->send( self::command( HarnessContract::ACTION_SENTINEL, array( AtomicLifecycleCheckpoints::AFTER_FIRST_SENTINEL_LOCK ), array(), null, null, 1, 2 ) );
				$workers[1]->send( self::command( HarnessContract::ACTION_SENTINEL, array( AtomicLifecycleCheckpoints::AFTER_FIRST_SENTINEL_LOCK ), array(), null, null, 2, 1 ) );
				$workers[0]->waitForType( HarnessContract::MESSAGE_CHECKPOINT, AtomicLifecycleCheckpoints::AFTER_FIRST_SENTINEL_LOCK );
				$workers[1]->waitForType( HarnessContract::MESSAGE_CHECKPOINT, AtomicLifecycleCheckpoints::AFTER_FIRST_SENTINEL_LOCK );
				$workers[0]->release( AtomicLifecycleCheckpoints::AFTER_FIRST_SENTINEL_LOCK );
				$workers[1]->release( AtomicLifecycleCheckpoints::AFTER_FIRST_SENTINEL_LOCK );
				$responses = array(
					$workers[0]->waitForType( HarnessContract::MESSAGE_RESULT ),
					$workers[1]->waitForType( HarnessContract::MESSAGE_RESULT ),
				);
			} finally {
				self::closeWorkers( $workers );
			}

			$deadlockIndex = HarnessContract::OUTCOME_DEADLOCK === ( $responses[0]['outcome'] ?? null ) ? 0 : 1;
			$retryFirst    = 0 === $deadlockIndex ? 1 : 2;
			$retrySecond   = 0 === $deadlockIndex ? 2 : 1;
			$retry         = self::runSingleAction(
				self::command( HarnessContract::ACTION_SENTINEL, array(), array(), null, null, $retryFirst, $retrySecond )
			);
			$values        = $store->sentinelValues();
			$after         = $store->snapshot();
			$deadlock      = self::firstOutcome( $responses, HarnessContract::OUTCOME_DEADLOCK );
			$passed        = 1 === self::outcomeCount( $responses, HarnessContract::OUTCOME_DEADLOCK )
				&& 1 === self::outcomeCount( $responses, HarnessContract::OUTCOME_WINNER )
				&& HarnessContract::OUTCOME_WINNER === $retry['outcome']
				&& 1 === ( $values[1] ?? -1 )
				&& 1 === ( $values[2] ?? -1 )
				&& 1213 === ( $deadlock['error_number'] ?? null )
				&& self::preservedDomain( $before, $after );

			return self::complete(
				$result,
				array(
					'responses_successful'      => 2,
					'committed_winners'         => 2,
					'rollbacks'                 => 1,
					'retries'                   => 1,
					'deadlocks'                 => 1,
					'distinct_connections'      => 3,
					'sentinel_residue'          => $passed ? 0 : 1,
					'error_number'              => is_int( $deadlock['error_number'] ?? null ) ? $deadlock['error_number'] : null,
					'sqlstate_class'            => is_string( $deadlock['sqlstate_class'] ?? null ) ? $deadlock['sqlstate_class'] : null,
					'unrelated_state_unchanged' => self::unrelatedUnchanged( $before, $after ),
					'sibling_domain_unchanged'  => self::unrelatedUnchanged( $before, $after ),
					'outcomes'                  => array( HarnessContract::OUTCOME_DEADLOCK, HarnessContract::OUTCOME_WINNER ),
				),
				$passed
			);
		} finally {
			$database->close();
		}
	}

	/**
	 * @return array<string, mixed>
	 */
	private static function runLockTimeout( LaneConfiguration $lane ): array {
		$result   = SanitizedResult::base( $lane, HarnessContract::CASE_LOCK_TIMEOUT, 2, 1 );
		$database = $lane->connect();
		$store    = new AtomicLifecycleStore( $database );

		try {
			self::seedScenario( HarnessContract::ACTION_SEED_CODE );
			$before    = $store->snapshot();
			$workers   = self::startWorkers( 2 );
			$lockPoint = AtomicLifecycleCheckpoints::AFTER_FIRST_SENTINEL_LOCK;

			try {
				$workers[0]->send( self::command( HarnessContract::ACTION_SENTINEL, array( $lockPoint ), array(), null, null, 1, 2 ) );
				$workers[0]->waitForType( HarnessContract::MESSAGE_CHECKPOINT, $lockPoint );
				$workers[1]->send( self::command( HarnessContract::ACTION_SENTINEL, array(), array(), null, null, 2, 1 ) );
				$timeout = $workers[1]->waitForType( HarnessContract::MESSAGE_RESULT );
				$workers[0]->release( $lockPoint );
				$holder = $workers[0]->waitForType( HarnessContract::MESSAGE_RESULT );
			} finally {
				self::closeWorkers( $workers );
			}

			$retry  = self::runSingleAction( self::command( HarnessContract::ACTION_SENTINEL, array(), array(), null, null, 2, 1 ) );
			$values = $store->sentinelValues();
			$after  = $store->snapshot();
			$passed = HarnessContract::OUTCOME_LOCK_TIMEOUT === $timeout['outcome']
				&& 1205 === $timeout['error_number']
				&& HarnessContract::OUTCOME_WINNER === $holder['outcome']
				&& HarnessContract::OUTCOME_WINNER === $retry['outcome']
				&& 1 === ( $values[1] ?? -1 )
				&& 1 === ( $values[2] ?? -1 )
				&& self::preservedDomain( $before, $after );

			return self::complete(
				$result,
				array(
					'responses_successful'      => 2,
					'committed_winners'         => 2,
					'rollbacks'                 => 1,
					'retries'                   => 1,
					'lock_timeouts'             => 1,
					'distinct_connections'      => 3,
					'sentinel_residue'          => $passed ? 0 : 1,
					'error_number'              => is_int( $timeout['error_number'] ) ? $timeout['error_number'] : null,
					'sqlstate_class'            => is_string( $timeout['sqlstate_class'] ) ? $timeout['sqlstate_class'] : null,
					'unrelated_state_unchanged' => self::unrelatedUnchanged( $before, $after ),
					'sibling_domain_unchanged'  => self::unrelatedUnchanged( $before, $after ),
					'outcomes'                  => array( HarnessContract::OUTCOME_LOCK_TIMEOUT, HarnessContract::OUTCOME_WINNER ),
				),
				$passed
			);
		} finally {
			$database->close();
		}
	}

	/**
	 * @return array<string, mixed>
	 */
	private static function runConnectionLoss( LaneConfiguration $lane ): array {
		$result   = SanitizedResult::base( $lane, HarnessContract::CASE_CONNECTION_LOSS, 1, 1 );
		$database = $lane->connect();
		$store    = new AtomicLifecycleStore( $database );

		try {
			self::seedScenario( HarnessContract::ACTION_SEED_CODE );
			$before    = $store->snapshot();
			$rawWorker = self::startWorkers( 1 )[0];
			$rawWorker->send( self::command( HarnessContract::ACTION_RAW_WPDB_CONNECTION_LOSS ) );
			$rawCheckpoint = $rawWorker->waitForCheckpointOrResult( AtomicLifecycleCheckpoints::AFTER_CONNECTION_MUTATION );
			if ( HarnessContract::MESSAGE_RESULT === ( $rawCheckpoint['type'] ?? null ) ) {
				$rawWorker->close();
				return self::complete(
					$result,
					array(
						'error_number' => is_int( $rawCheckpoint['error_number'] ?? null ) ? $rawCheckpoint['error_number'] : null,
						'outcomes'     => array( HarnessContract::OUTCOME_FAILED ),
					),
					false
				);
			}
			self::killConnection( $database, self::messageConnectionId( $rawCheckpoint ) );
			$rawWorker->release( AtomicLifecycleCheckpoints::AFTER_CONNECTION_MUTATION );
			$raw = $rawWorker->waitForType( HarnessContract::MESSAGE_RESULT );
			if ( 0 !== $rawWorker->close() ) {
				throw new RuntimeException( 'Raw wpdb worker emitted unexpected diagnostics or exit status.' );
			}
			if ( HarnessContract::OUTCOME_FAILED === ( $raw['outcome'] ?? null ) ) {
				return self::complete(
					$result,
					array(
						'error_number' => is_int( $raw['error_number'] ?? null ) ? $raw['error_number'] : null,
						'outcomes'     => array( HarnessContract::OUTCOME_FAILED ),
					),
					false
				);
			}
			$rawValues = $store->sentinelValues();

			self::seedScenario( HarnessContract::ACTION_SEED_CODE );
			$ownedWorker = self::startWorkers( 1 )[0];
			$ownedWorker->send(
				self::command(
					HarnessContract::ACTION_CONNECTION_LOSS,
					array( AtomicLifecycleCheckpoints::AFTER_CONNECTION_MUTATION )
				)
			);
			$ownedCheckpoint = $ownedWorker->waitForType( HarnessContract::MESSAGE_CHECKPOINT, AtomicLifecycleCheckpoints::AFTER_CONNECTION_MUTATION );
			self::killConnection( $database, self::messageConnectionId( $ownedCheckpoint ) );
			$ownedWorker->release( AtomicLifecycleCheckpoints::AFTER_CONNECTION_MUTATION );
			$owned = $ownedWorker->waitForType( HarnessContract::MESSAGE_RESULT );
			if ( 0 !== $ownedWorker->close() ) {
				throw new RuntimeException( 'Owned-connection worker emitted unexpected diagnostics or exit status.' );
			}
			$ownedValues = $store->sentinelValues();
			$retry       = self::runSingleAction( self::command( HarnessContract::ACTION_CONNECTION_LOSS ) );
			$after       = $store->snapshot();
			$retryValues = $store->sentinelValues();
			$rawRed      = true === $raw['raw_wpdb_replayed_outside_transaction']
				&& 0 === ( $rawValues[1] ?? -1 )
				&& 1 === ( $rawValues[2] ?? -1 );
			$green       = HarnessContract::OUTCOME_CONNECTION_LOST === $owned['outcome']
				&& in_array( $owned['error_number'], array( 2006, 2013 ), true )
				&& array(
					1 => 0,
					2 => 0,
				) === $ownedValues
				&& HarnessContract::OUTCOME_WINNER === $retry['outcome']
				&& array(
					1 => 1,
					2 => 0,
				) === $retryValues;
			$passed      = $rawRed && $green && self::preservedDomain( $before, $after );

			return self::complete(
				$result,
				array(
					'responses_successful'         => 1,
					'committed_winners'            => 1,
					'rollbacks'                    => 1,
					'retries'                      => 1,
					'connection_losses'            => 2,
					'distinct_connections'         => 3,
					'sentinel_residue'             => $green ? 0 : 1,
					'raw_wpdb_replayed_outside_transaction' => $rawRed,
					'owned_connection_fail_closed' => $green,
					'error_number'                 => is_int( $owned['error_number'] ) ? $owned['error_number'] : null,
					'sqlstate_class'               => is_string( $owned['sqlstate_class'] ) ? $owned['sqlstate_class'] : null,
					'unrelated_state_unchanged'    => self::unrelatedUnchanged( $before, $after ),
					'sibling_domain_unchanged'     => self::unrelatedUnchanged( $before, $after ),
					'outcomes'                     => array( HarnessContract::OUTCOME_CONNECTION_LOST, HarnessContract::OUTCOME_WINNER ),
				),
				$passed
			);
		} catch ( Throwable ) {
			return self::complete(
				$result,
				array(
					'outcomes' => array( HarnessContract::OUTCOME_FAILED ),
				),
				false
			);
		} finally {
			$database->close();
		}
	}

	/**
	 * @param array<string, bool|int|string|list<string>> $command Worker command.
	 * @return array<string, mixed>
	 */
	private static function runSingleAction( array $command ): array {
		$worker   = self::startWorkers( 1 )[0];
		$response = array();

		try {
			$worker->send( $command );
			$response = $worker->waitForType( HarnessContract::MESSAGE_RESULT );
		} finally {
			$exitCode = $worker->close();
			if ( 0 !== $exitCode ) {
				throw new RuntimeException( 'Worker emitted unexpected diagnostics or exit status.' );
			}
		}

		return $response;
	}

	private static function seedScenario( string $action ): void {
		$result = self::runSingleAction( self::command( $action ) );

		if (
			HarnessContract::OUTCOME_WINNER !== ( $result['outcome'] ?? null )
			|| true !== ( $result['committed'] ?? null )
		) {
			throw new RuntimeException( 'Disposable proof scenario could not be seeded.' );
		}
	}

	/**
	 * @return list<WorkerProcess>
	 */
	private static function startWorkers( int $count ): array {
		$workers = array();

		try {
			for ( $workerId = 0; $workerId < $count; ++$workerId ) {
				$worker = new WorkerProcess( $workerId );
				$worker->start();
				$workers[] = $worker;
			}

			return $workers;
		} catch ( Throwable $failure ) {
			self::closeWorkers( $workers );
			throw $failure;
		}
	}

	/**
	 * @param list<WorkerProcess> $workers Workers to reap.
	 */
	private static function closeWorkers( array $workers ): void {
		foreach ( $workers as $worker ) {
			$exitCode = $worker->close();
			if ( 0 !== $exitCode ) {
				throw new RuntimeException( 'Worker emitted unexpected diagnostics or exit status.' );
			}
		}
	}

	/**
	 * Builds one complete fixed worker command.
	 *
	 * @param list<string> $holdAt Checkpoints to hold.
	 * @param list<string> $failAt Checkpoints to fail.
	 * @return array<string, bool|int|string|list<string>>
	 */
	private static function command(
		string $action,
		array $holdAt = array(),
		array $failAt = array(),
		?string $exitAt = null,
		?int $generation = null,
		int $firstSentinel = 1,
		int $secondSentinel = 2
	): array {
		return array(
			'command'           => HarnessContract::COMMAND_RUN,
			'action'            => $action,
			'hold_at'           => $holdAt,
			'fail_at'           => $failAt,
			'exit_at'           => $exitAt ?? '',
			'generation'        => $generation ?? 0,
			'first_sentinel'    => $firstSentinel,
			'second_sentinel'   => $secondSentinel,
			'lock_wait_timeout' => HarnessContract::DEFAULT_LOCK_WAIT_TIMEOUT_SECONDS,
		);
	}

	/**
	 * @param array<string, mixed> $result Base result.
	 * @param array<string, mixed> $fields Changed fields.
	 * @return array<string, mixed>
	 */
	private static function complete( array $result, array $fields, bool $passed ): array {
		foreach ( $fields as $key => $value ) {
			if ( array_key_exists( $key, $result ) ) {
				$result[ $key ] = $value;
			}
		}

		$result['status'] = $passed ? HarnessContract::OUTCOME_PASSED : HarnessContract::OUTCOME_FAILED;
		$result['passed'] = $passed;

		if ( ! SanitizedResult::validate( $result ) ) {
			throw new RuntimeException( 'Harness result failed its fixed output contract.' );
		}

		return $result;
	}

	/**
	 * @return array<string, int|bool>
	 */
	private static function snapshotFields( AtomicLifecycleSnapshot $snapshot ): array {
		return array(
			'committed_code_lineages'   => $snapshot->committedCodeLineageCount(),
			'valid_code_descendants'    => $snapshot->validCodeDescendantCount(),
			'active_refresh_members'    => $snapshot->currentRefreshCount(),
			'active_access_credentials' => $snapshot->activeAccessCount(),
			'family_terminal'           => in_array( $snapshot->familyState(), array( 'revoked', 'compromised' ), true ),
			'grant_terminal'            => 'revoked' === $snapshot->grantState(),
		);
	}

	private static function preservedDomain( AtomicLifecycleSnapshot $before, AtomicLifecycleSnapshot $after ): bool {
		return self::unrelatedUnchanged( $before, $after ) && $before->bindings() === $after->bindings();
	}

	private static function unrelatedUnchanged( AtomicLifecycleSnapshot $before, AtomicLifecycleSnapshot $after ): bool {
		return $before->unrelatedState() === $after->unrelatedState();
	}

	/**
	 * @param list<array<string, mixed>> $responses Worker results.
	 */
	private static function outcomeCount( array $responses, string $outcome ): int {
		return count(
			array_filter(
				$responses,
				static fn( array $response ): bool => ( $response['outcome'] ?? null ) === $outcome
			)
		);
	}

	/**
	 * @param list<array<string, mixed>> $responses Worker results.
	 * @return array<string, mixed>
	 */
	private static function firstOutcome( array $responses, string $outcome ): array {
		foreach ( $responses as $response ) {
			if ( ( $response['outcome'] ?? null ) === $outcome ) {
				return $response;
			}
		}

		return array();
	}

	/**
	 * @param array<string, mixed> $message Worker message.
	 */
	private static function messageConnectionId( array $message ): int {
		$value = $message['connection_id'] ?? null;

		if ( ! is_int( $value ) || 1 > $value ) {
			throw new RuntimeException( 'Worker checkpoint connection identity was invalid.' );
		}

		return $value;
	}

	private static function killConnection( \mysqli $database, int $connectionId ): void {
		if ( 1 > $connectionId || true !== $database->query( 'KILL CONNECTION ' . $connectionId ) ) {
			throw new RuntimeException( 'Disposable worker connection could not be terminated.' );
		}
	}

	private static function serverVersionMatches( \mysqli $database, LaneConfiguration $lane ): bool {
		$result = $database->query( 'SELECT VERSION() AS server_version' );
		$row    = $result instanceof mysqli_result ? $result->fetch_assoc() : null;

		if ( $result instanceof mysqli_result ) {
			$result->free();
		}

		$observed = is_array( $row ) ? (string) $row['server_version'] : '';

		return str_starts_with( $observed, $lane->databaseVersion() )
			&& ( 'mariadb' === $lane->databaseFamily() ) === str_contains( strtolower( $observed ), 'mariadb' );
	}

	private static function isolationMatches( \mysqli $database, LaneConfiguration $lane ): bool {
		$variable = 'mariadb' === $lane->databaseFamily() ? '@@tx_isolation' : '@@transaction_isolation';
		$result   = $database->query( "SELECT {$variable} AS isolation_value" );
		$row      = $result instanceof mysqli_result ? $result->fetch_assoc() : null;

		if ( $result instanceof mysqli_result ) {
			$result->free();
		}

		$observed = is_array( $row ) ? str_replace( '-', ' ', strtoupper( (string) $row['isolation_value'] ) ) : '';

		return $lane->isolation() === $observed;
	}

	private static function snapshotIsolationMatches( \mysqli $database, LaneConfiguration $lane ): bool {
		if ( 'mysql' === $lane->databaseFamily() ) {
			return null === $lane->snapshotIsolation();
		}

		$result = $database->query( 'SELECT @@innodb_snapshot_isolation AS snapshot_isolation' );
		$row    = $result instanceof mysqli_result ? $result->fetch_assoc() : null;

		if ( $result instanceof mysqli_result ) {
			$result->free();
		}

		return is_array( $row ) && (int) $row['snapshot_isolation'] === (int) $lane->snapshotIsolation();
	}

	private static function autocommitIsOn( \mysqli $database ): bool {
		$result = $database->query( 'SELECT @@autocommit AS autocommit_value' );
		$row    = $result instanceof mysqli_result ? $result->fetch_assoc() : null;

		if ( $result instanceof mysqli_result ) {
			$result->free();
		}

		return is_array( $row ) && 1 === (int) $row['autocommit_value'];
	}

	private static function serverIsReadWrite( \mysqli $database ): bool {
		$result = $database->query( 'SELECT @@global.read_only AS read_only_value' );
		$row    = $result instanceof mysqli_result ? $result->fetch_assoc() : null;

		if ( $result instanceof mysqli_result ) {
			$result->free();
		}

		return is_array( $row ) && 0 === (int) $row['read_only_value'];
	}

	private static function serverSqlMode( \mysqli $database ): string {
		$result = $database->query( 'SELECT @@sql_mode AS sql_mode_value' );
		$row    = $result instanceof mysqli_result ? $result->fetch_assoc() : null;

		if ( $result instanceof mysqli_result ) {
			$result->free();
		}

		$mode = is_array( $row ) ? strtoupper( (string) $row['sql_mode_value'] ) : '';

		return 1024 >= strlen( $mode ) && preg_match( '/^[A-Z0-9_,]+$/D', $mode ) ? $mode : '';
	}

	private static function galeraEnabled( \mysqli $database, LaneConfiguration $lane ): bool {
		if ( 'mysql' === $lane->databaseFamily() ) {
			return false;
		}

		$result = $database->query( 'SELECT @@wsrep_on AS wsrep_value' );
		$row    = $result instanceof mysqli_result ? $result->fetch_assoc() : null;

		if ( $result instanceof mysqli_result ) {
			$result->free();
		}

		return ! is_array( $row ) || 0 !== (int) $row['wsrep_value'];
	}
}
