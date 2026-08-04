<?php
/**
 * Slice 0 concurrent atomic-lifecycle harness integration tests.
 *
 * @package GalatanOvidiu\Charter
 */

declare(strict_types=1);

namespace GalatanOvidiu\Charter\Tests\Integration\AtomicLifecycle;

use GalatanOvidiu\Charter\Tests\Fixtures\AtomicLifecycle\AtomicLifecycleHarness;
use GalatanOvidiu\Charter\Tests\Fixtures\AtomicLifecycle\HarnessContract;
use GalatanOvidiu\Charter\Tests\Fixtures\AtomicLifecycle\LaneConfiguration;
use GalatanOvidiu\Charter\Tests\Fixtures\AtomicLifecycle\SanitizedResult;
use GalatanOvidiu\Charter\Tests\Prototype\AtomicLifecycle\AtomicLifecycleSchema;
use PHPUnit\Framework\TestCase;

require_once dirname( __DIR__, 2 ) . '/fixtures/atomic-lifecycle/HarnessContract.php';
require_once dirname( __DIR__, 2 ) . '/fixtures/atomic-lifecycle/LaneConfiguration.php';
require_once dirname( __DIR__, 2 ) . '/fixtures/atomic-lifecycle/SanitizedResult.php';
require_once dirname( __DIR__, 2 ) . '/fixtures/atomic-lifecycle/WorkerProcess.php';
require_once dirname( __DIR__, 2 ) . '/fixtures/atomic-lifecycle/RawWpdbReconnectProbe.php';
require_once dirname( __DIR__, 2 ) . '/fixtures/atomic-lifecycle/AtomicLifecycleHarness.php';

/**
 * Proves concurrent and failure semantics through fixed sanitized case results.
 *
 * @since 0.1.0
 */
final class ConcurrentLifecycleHarnessTest extends TestCase {

	/**
	 * Current disposable database lane.
	 *
	 * @since 0.1.0
	 *
	 * @var LaneConfiguration|null
	 */
	private ?LaneConfiguration $lane = null;

	/**
	 * Creates a fresh fixture only inside a runner-provisioned lane.
	 *
	 * @since 0.1.0
	 */
	protected function setUp(): void {
		parent::setUp();

		$databaseHost = getenv( 'CHARTER_ATOMIC_DB_HOST' );
		if ( false === $databaseHost || '' === $databaseHost ) {
			self::markTestSkipped( 'The disposable atomic-lifecycle lane is not provisioned.' );
		}

		$this->lane = LaneConfiguration::fromEnvironment();
		AtomicLifecycleHarness::createFixture( $this->lane );
	}

	/**
	 * Removes the exact fixture and verifies no proof table remains.
	 *
	 * @since 0.1.0
	 */
	protected function tearDown(): void {
		if ( $this->lane instanceof LaneConfiguration ) {
			AtomicLifecycleHarness::dropFixture( $this->lane );
			self::assertSame( 0, AtomicLifecycleHarness::cleanupTablesRemaining( $this->lane ) );
		}

		$this->lane = null;

		parent::tearDown();
	}

	/**
	 * Verifies exact database capability and distinct-worker preflight.
	 *
	 * @since 0.1.0
	 */
	public function testCapabilityPreflightUsesDistinctConnectionsAndCleanRollback(): void {
		$workers = self::workerCount();
		$result  = AtomicLifecycleHarness::runCase(
			HarnessContract::CASE_PREFLIGHT,
			$this->lane(),
			$workers,
			1
		);

		self::assertPassedResult( $result, false );
		self::assertSame( $workers, $result['distinct_connections'] );
		self::assertSame( 1, $result['rollbacks'] );
		self::assertTrue( $result['constraints_enforced'] );
		self::assertTrue( $result['autocommit_initial'] );
		self::assertTrue( $result['read_write'] );
		self::assertFalse( $result['proxied'] );
		self::assertFalse( $result['replicated'] );
		self::assertFalse( $result['galera'] );
		self::assertSame( array( HarnessContract::OUTCOME_ROLLED_BACK ), $result['outcomes'] );
	}

	/**
	 * Verifies ordinary exchange and later replay/invalid-input containment.
	 *
	 * @since 0.1.0
	 */
	public function testCodeExchangeAndReplayHaveCaseSpecificCommittedCounts(): void {
		$exchange = AtomicLifecycleHarness::runCase(
			HarnessContract::CASE_CODE_EXCHANGE,
			$this->lane(),
			1,
			1
		);

		self::assertPassedResult( $exchange );
		self::assertResultCounts(
			$exchange,
			array(
				'responses_successful'      => 1,
				'committed_winners'         => 1,
				'replays'                   => 0,
				'committed_code_lineages'   => 1,
				'valid_code_descendants'    => 3,
				'active_refresh_members'    => 1,
				'active_access_credentials' => 1,
			)
		);
		self::assertFalse( $exchange['family_terminal'] );
		self::assertFalse( $exchange['grant_terminal'] );

		$replay = AtomicLifecycleHarness::runCase(
			HarnessContract::CASE_CODE_REPLAY,
			$this->lane(),
			1,
			1
		);

		self::assertPassedResult( $replay );
		self::assertResultCounts(
			$replay,
			array(
				'responses_successful'      => 2,
				'committed_winners'         => 2,
				'replays'                   => 2,
				'replay_events'             => 1,
				'committed_code_lineages'   => 1,
				'valid_code_descendants'    => 0,
				'active_refresh_members'    => 0,
				'active_access_credentials' => 0,
			)
		);
		self::assertTrue( $replay['family_terminal'] );
		self::assertFalse( $replay['grant_terminal'] );
		self::assertSame(
			array(
				HarnessContract::OUTCOME_WINNER,
				HarnessContract::OUTCOME_REPLAY,
				HarnessContract::OUTCOME_INVALID,
			),
			$replay['outcomes']
		);
	}

	/**
	 * Verifies every decisive code-race round has one winner and terminal replay.
	 *
	 * @since 0.1.0
	 */
	public function testCodeRaceHasOneWinnerPerRoundAndNoAcceptedDescendant(): void {
		$workers = self::workerCount();
		$rounds  = self::roundCount();
		$result  = AtomicLifecycleHarness::runCase(
			HarnessContract::CASE_CODE_RACE,
			$this->lane(),
			$workers,
			$rounds
		);

		self::assertPassedResult( $result );
		self::assertResultCounts(
			$result,
			array(
				'workers'                   => $workers,
				'rounds'                    => $rounds,
				'responses_successful'      => $rounds,
				'committed_winners'         => $rounds,
				'replays'                   => $rounds * ( $workers - 1 ),
				'replay_events'             => $rounds,
				'distinct_connections'      => $workers,
				'committed_code_lineages'   => 1,
				'valid_code_descendants'    => 0,
				'active_refresh_members'    => 0,
				'active_access_credentials' => 0,
			)
		);
		self::assertTrue( $result['family_terminal'] );
		self::assertFalse( $result['grant_terminal'] );
	}

	/**
	 * Verifies worker death rolls back and lost commit response fails closed.
	 *
	 * @since 0.1.0
	 */
	public function testWorkerDeathAndCommitAmbiguityRecoverFromAuthoritativeState(): void {
		$death = AtomicLifecycleHarness::runCase(
			HarnessContract::CASE_CODE_WORKER_DEATH,
			$this->lane(),
			1,
			1
		);

		self::assertPassedResult( $death );
		self::assertResultCounts(
			$death,
			array(
				'responses_successful'      => 1,
				'committed_winners'         => 1,
				'rollbacks'                 => 1,
				'retries'                   => 1,
				'worker_deaths'             => 1,
				'committed_code_lineages'   => 1,
				'valid_code_descendants'    => 3,
				'active_refresh_members'    => 1,
				'active_access_credentials' => 1,
			)
		);

		$ambiguity = AtomicLifecycleHarness::runCase(
			HarnessContract::CASE_CODE_COMMIT_AMBIGUITY,
			$this->lane(),
			1,
			1
		);

		self::assertPassedResult( $ambiguity );
		self::assertResultCounts(
			$ambiguity,
			array(
				'responses_successful'      => 0,
				'committed_winners'         => 1,
				'replays'                   => 1,
				'retries'                   => 1,
				'worker_deaths'             => 1,
				'replay_events'             => 1,
				'committed_code_lineages'   => 1,
				'valid_code_descendants'    => 0,
				'active_refresh_members'    => 0,
				'active_access_credentials' => 0,
			)
		);
		self::assertTrue( $ambiguity['family_terminal'] );
		self::assertFalse( $ambiguity['grant_terminal'] );
	}

	/**
	 * Verifies rotation and retained-ancestor replay preserve exact containment.
	 *
	 * @since 0.1.0
	 */
	public function testRefreshRotationAndAncestorReplayHaveExactTerminalState(): void {
		$rotation = AtomicLifecycleHarness::runCase(
			HarnessContract::CASE_REFRESH_ROTATION,
			$this->lane(),
			1,
			1
		);

		self::assertPassedResult( $rotation );
		self::assertResultCounts(
			$rotation,
			array(
				'responses_successful'      => 1,
				'committed_winners'         => 1,
				'committed_code_lineages'   => 0,
				'valid_code_descendants'    => 0,
				'active_refresh_members'    => 1,
				'active_access_credentials' => 3,
			)
		);
		self::assertFalse( $rotation['family_terminal'] );
		self::assertFalse( $rotation['grant_terminal'] );

		$replay = AtomicLifecycleHarness::runCase(
			HarnessContract::CASE_REFRESH_ANCESTOR_REPLAY,
			$this->lane(),
			1,
			1
		);

		self::assertPassedResult( $replay );
		self::assertResultCounts(
			$replay,
			array(
				'responses_successful'      => 2,
				'committed_winners'         => 2,
				'replays'                   => 2,
				'replay_events'             => 1,
				'committed_code_lineages'   => 0,
				'valid_code_descendants'    => 0,
				'active_refresh_members'    => 0,
				'active_access_credentials' => 0,
			)
		);
		self::assertTrue( $replay['family_terminal'] );
		self::assertTrue( $replay['grant_terminal'] );
	}

	/**
	 * Verifies every decisive refresh-race round cascades through the winner.
	 *
	 * @since 0.1.0
	 */
	public function testRefreshRaceHasOneWinnerPerRoundAndTerminalFamily(): void {
		$workers = self::workerCount();
		$rounds  = self::roundCount();
		$result  = AtomicLifecycleHarness::runCase(
			HarnessContract::CASE_REFRESH_RACE,
			$this->lane(),
			$workers,
			$rounds
		);

		self::assertPassedResult( $result );
		self::assertResultCounts(
			$result,
			array(
				'workers'                   => $workers,
				'rounds'                    => $rounds,
				'responses_successful'      => $rounds,
				'committed_winners'         => $rounds,
				'replays'                   => $rounds * ( $workers - 1 ),
				'replay_events'             => $rounds,
				'distinct_connections'      => $workers,
				'committed_code_lineages'   => 0,
				'valid_code_descendants'    => 0,
				'active_refresh_members'    => 0,
				'active_access_credentials' => 0,
			)
		);
		self::assertTrue( $result['family_terminal'] );
		self::assertTrue( $result['grant_terminal'] );
	}

	/**
	 * Verifies deadlock and timeout retries discard the failed transaction.
	 *
	 * @since 0.1.0
	 */
	public function testDeadlockAndLockTimeoutRetriesLeaveNoSentinelResidue(): void {
		$deadlock = AtomicLifecycleHarness::runCase(
			HarnessContract::CASE_DEADLOCK,
			$this->lane(),
			2,
			1
		);

		self::assertPassedResult( $deadlock );
		self::assertResultCounts(
			$deadlock,
			array(
				'responses_successful' => 2,
				'committed_winners'    => 2,
				'rollbacks'            => 1,
				'retries'              => 1,
				'deadlocks'            => 1,
				'distinct_connections' => 3,
				'sentinel_residue'     => 0,
			)
		);
		self::assertSame( 1213, $deadlock['error_number'] );
		$deadlockSqlState = $deadlock['sqlstate_class'];
		self::assertIsString( $deadlockSqlState );
		self::assertMatchesRegularExpression( '/^[A-Z0-9]{2}$/D', $deadlockSqlState );

		$timeout = AtomicLifecycleHarness::runCase(
			HarnessContract::CASE_LOCK_TIMEOUT,
			$this->lane(),
			2,
			1
		);

		self::assertPassedResult( $timeout );
		self::assertResultCounts(
			$timeout,
			array(
				'responses_successful' => 2,
				'committed_winners'    => 2,
				'rollbacks'            => 1,
				'retries'              => 1,
				'lock_timeouts'        => 1,
				'distinct_connections' => 3,
				'sentinel_residue'     => 0,
			)
		);
		self::assertSame( 1205, $timeout['error_number'] );
		$timeoutSqlState = $timeout['sqlstate_class'];
		self::assertIsString( $timeoutSqlState );
		self::assertMatchesRegularExpression( '/^[A-Z0-9]{2}$/D', $timeoutSqlState );
	}

	/**
	 * Verifies raw wpdb replay is red while the owned connection fails closed.
	 *
	 * @since 0.1.0
	 */
	public function testConnectionLossBoundaryDetectsAndContainsStatementReplay(): void {
		$result = AtomicLifecycleHarness::runCase(
			HarnessContract::CASE_CONNECTION_LOSS,
			$this->lane(),
			1,
			1
		);

		self::assertPassedResult( $result );
		self::assertResultCounts(
			$result,
			array(
				'responses_successful' => 1,
				'committed_winners'    => 1,
				'rollbacks'            => 1,
				'retries'              => 1,
				'connection_losses'    => 2,
				'distinct_connections' => 3,
				'sentinel_residue'     => 0,
			)
		);
		self::assertTrue( $result['raw_wpdb_replayed_outside_transaction'] );
		self::assertTrue( $result['owned_connection_fail_closed'] );
		self::assertTrue( in_array( $result['error_number'], array( 2006, 2013 ), true ) );
		self::assertContains( $result['sqlstate_class'], array( '08', 'HY' ) );
	}

	/**
	 * Verifies fixture teardown removes only all seven P1 proof tables.
	 *
	 * @since 0.1.0
	 */
	public function testFixtureCleanupLeavesNoProofTablesOrWorkerProcesses(): void {
		self::assertSame(
			count( AtomicLifecycleSchema::tableNames() ),
			AtomicLifecycleHarness::cleanupTablesRemaining( $this->lane() )
		);

		AtomicLifecycleHarness::dropFixture( $this->lane() );

		self::assertSame( 0, AtomicLifecycleHarness::cleanupTablesRemaining( $this->lane() ) );
	}

	/**
	 * Asserts the common sanitized success and residue contract.
	 *
	 * @since 0.1.0
	 *
	 * @param array<string, mixed> $result Harness case result.
	 * @param bool                 $domainExpected Whether domain-preservation fields apply.
	 */
	private static function assertPassedResult( array $result, bool $domainExpected = true ): void {
		self::assertTrue( SanitizedResult::validate( $result ) );
		self::assertSame( HarnessContract::OUTCOME_PASSED, $result['status'] );
		self::assertTrue( $result['passed'] );
		self::assertSame( 0, $result['cleanup_tables_remaining'] );
		self::assertSame( 0, $result['worker_processes_remaining'] );

		if ( $domainExpected ) {
			self::assertTrue( $result['unrelated_state_unchanged'] );
			self::assertTrue( $result['sibling_domain_unchanged'] );
		}
	}

	/**
	 * Asserts an exact subset of numeric case counters.
	 *
	 * @since 0.1.0
	 *
	 * @param array<string, mixed> $result Harness case result.
	 * @param array<string, int>   $expected Expected field values.
	 */
	private static function assertResultCounts( array $result, array $expected ): void {
		foreach ( $expected as $field => $value ) {
			self::assertSame( $value, $result[ $field ], 'Unexpected harness count for ' . $field . '.' );
		}
	}

	/**
	 * Returns the initialized disposable lane configuration.
	 *
	 * @since 0.1.0
	 */
	private function lane(): LaneConfiguration {
		self::assertInstanceOf( LaneConfiguration::class, $this->lane );

		return $this->lane;
	}

	/**
	 * Reads the bounded decisive worker-count override.
	 *
	 * @since 0.1.0
	 */
	private static function workerCount(): int {
		return HarnessContract::boundedEnvironmentInteger(
			'CHARTER_ATOMIC_WORKERS',
			HarnessContract::DEFAULT_WORKERS,
			HarnessContract::MINIMUM_DECISIVE_WORKERS,
			HarnessContract::MAXIMUM_WORKERS
		);
	}

	/**
	 * Reads the bounded decisive race-round override.
	 *
	 * @since 0.1.0
	 */
	private static function roundCount(): int {
		return HarnessContract::boundedEnvironmentInteger(
			'CHARTER_ATOMIC_ROUNDS',
			HarnessContract::DEFAULT_ROUNDS,
			HarnessContract::MINIMUM_DECISIVE_ROUNDS,
			HarnessContract::MAXIMUM_ROUNDS
		);
	}
}
