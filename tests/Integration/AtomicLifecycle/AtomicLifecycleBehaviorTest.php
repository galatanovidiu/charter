<?php
/**
 * Slice 0 atomic-lifecycle database behavior integration tests.
 *
 * @package GalatanOvidiu\Charter
 */

declare(strict_types=1);

namespace GalatanOvidiu\Charter\Tests\Integration\AtomicLifecycle;

use GalatanOvidiu\Charter\Tests\Fixtures\AtomicLifecycle\LaneConfiguration;
use GalatanOvidiu\Charter\Tests\Prototype\AtomicLifecycle\AtomicLifecycleCheckpoints;
use GalatanOvidiu\Charter\Tests\Prototype\AtomicLifecycle\AtomicLifecycleSchema;
use GalatanOvidiu\Charter\Tests\Prototype\AtomicLifecycle\AtomicLifecycleStore;
use GalatanOvidiu\Charter\Tests\Prototype\AtomicLifecycle\TransitionControl;
use GalatanOvidiu\Charter\Tests\Prototype\AtomicLifecycle\TransitionFailure;
use GalatanOvidiu\Charter\Tests\Prototype\AtomicLifecycle\TransitionResult;
use mysqli;
use PHPUnit\Framework\TestCase;

require_once dirname( __DIR__, 2 ) . '/fixtures/atomic-lifecycle/HarnessContract.php';
require_once dirname( __DIR__, 2 ) . '/fixtures/atomic-lifecycle/LaneConfiguration.php';

/**
 * Proves lifecycle semantics through the disposable store's public seam.
 *
 * @since 0.1.0
 */
final class AtomicLifecycleBehaviorTest extends TestCase {

	private const OPERATION_CODE_EXCHANGE = 'code_exchange';

	private const OPERATION_CODE_REPLAY = 'code_replay';

	private const OPERATION_REFRESH_ROTATION = 'refresh_rotation';

	private const OPERATION_REFRESH_REPLAY = 'refresh_replay';

	/**
	 * Current disposable database lane.
	 *
	 * @since 0.1.0
	 *
	 * @var LaneConfiguration|null
	 */
	private ?LaneConfiguration $lane = null;

	/**
	 * Independent connection owned by this test.
	 *
	 * @since 0.1.0
	 *
	 * @var mysqli|null
	 */
	private ?mysqli $database = null;

	/**
	 * Public disposable transition seam under test.
	 *
	 * @since 0.1.0
	 *
	 * @var AtomicLifecycleStore|null
	 */
	private ?AtomicLifecycleStore $store = null;

	/**
	 * Creates a fresh proof schema only inside a runner-provisioned lane.
	 *
	 * @since 0.1.0
	 */
	protected function setUp(): void {
		parent::setUp();

		$databaseHost = getenv( 'CHARTER_ATOMIC_DB_HOST' );
		if ( false === $databaseHost || '' === $databaseHost ) {
			self::markTestSkipped( 'The disposable atomic-lifecycle lane is not provisioned.' );
		}

		$this->lane     = LaneConfiguration::fromEnvironment();
		$this->database = $this->lane->connect();

		AtomicLifecycleSchema::drop( $this->database );
		AtomicLifecycleSchema::create( $this->database );

		$this->store = new AtomicLifecycleStore( $this->database );
	}

	/**
	 * Removes only the exact disposable proof tables after every case.
	 *
	 * @since 0.1.0
	 */
	protected function tearDown(): void {
		if ( $this->database instanceof mysqli ) {
			AtomicLifecycleSchema::drop( $this->database );
			$this->database->close();
		}

		$this->store    = null;
		$this->database = null;
		$this->lane     = null;

		parent::tearDown();
	}

	/**
	 * Verifies InnoDB, unique invariants, rollback, and distinct connections.
	 *
	 * @since 0.1.0
	 */
	public function testCapabilityPreflightAndCleanRollbackSentinel(): void {
		$database     = $this->database();
		$capabilities = AtomicLifecycleSchema::capabilities( $database );

		self::assertSame(
			array(
				'tables_present'            => true,
				'table_count'               => count( AtomicLifecycleSchema::tableNames() ),
				'all_innodb'                => true,
				'unique_invariants_present' => true,
			),
			$capabilities
		);

		$secondConnection = $this->lane()->connect();

		try {
			$secondStore = new AtomicLifecycleStore( $secondConnection );

			self::assertNotSame(
				$this->store()->connectionId(),
				$secondStore->connectionId(),
				'Independent proof actors shared one physical database connection.'
			);
		} finally {
			$secondConnection->close();
		}

		$this->store()->seedCodeScenario();
		$before = $this->store()->sentinelValues();

		try {
			$this->store()->exerciseSentinelTransition(
				1,
				2,
				new TransitionControl( null, array( AtomicLifecycleCheckpoints::AFTER_FIRST_SENTINEL_LOCK ) )
			);
			self::fail( 'The injected sentinel transition unexpectedly committed.' );
		} catch ( TransitionFailure $failure ) {
			self::assertSame( TransitionFailure::INJECTED, $failure->classification() );
		}

		self::assertSame( $before, $this->store()->sentinelValues() );

		$retry = $this->store()->exerciseSentinelTransition( 1, 2 );

		self::assertWinner( $retry );
		self::assertSame(
			array(
				1 => 1,
				2 => 0,
			),
			$this->store()->sentinelValues()
		);
	}

	/**
	 * Verifies one complete code exchange and all original bindings.
	 *
	 * @since 0.1.0
	 */
	public function testCodeExchangeCommitsExactlyOneBoundLineage(): void {
		$this->store()->seedCodeScenario();
		$before = $this->store()->snapshot();
		$result = $this->store()->exchangeCode();
		$after  = $this->store()->snapshot();

		self::assertWinner( $result );
		self::assertSame( 'consumed', $after->codeState() );
		self::assertSame( 'active', $after->grantState() );
		self::assertSame( 'active', $after->familyState() );
		self::assertSame( 0, $after->familyCurrentGeneration() );
		self::assertSame( 1, $after->committedCodeLineageCount() );
		self::assertSame( 3, $after->validCodeDescendantCount() );
		self::assertSame( 1, $after->activeAccessCount() );
		self::assertSame( 1, $after->currentRefreshCount() );
		self::assertSame( $before->bindings(), $after->bindings() );
		self::assertSame( $before->unrelatedState(), $after->unrelatedState() );
	}

	/**
	 * Verifies consumed-code replay is exact, terminal, and idempotent.
	 *
	 * @since 0.1.0
	 */
	public function testCodeReplayRevokesOnlyItsDescendantsAndIsIdempotent(): void {
		$this->store()->seedCodeScenario();
		$this->store()->exchangeCode();
		$this->store()->rotateRefresh( 0 );
		$beforeReplay = $this->store()->snapshot();
		self::assertSame( 4, $beforeReplay->validCodeDescendantCount() );
		self::assertSame( 2, $beforeReplay->activeAccessCount() );

		$firstReplay = $this->store()->exchangeCode();
		$terminal    = $this->store()->snapshot();

		self::assertReplay( $firstReplay );
		self::assertSame( 'replay', $terminal->codeState() );
		self::assertSame( 'active', $terminal->grantState() );
		self::assertSame( 'revoked', $terminal->familyState() );
		self::assertSame( 1, $terminal->committedCodeLineageCount() );
		self::assertSame( 0, $terminal->validCodeDescendantCount() );
		self::assertSame( 0, $terminal->activeAccessCount() );
		self::assertSame( 0, $terminal->currentRefreshCount() );
		self::assertSame( 1, $terminal->codeReplayEventCount() );
		self::assertSame( $beforeReplay->bindings(), $terminal->bindings() );
		self::assertSame( $beforeReplay->unrelatedState(), $terminal->unrelatedState() );

		$secondReplay = $this->store()->exchangeCode();
		$idempotent   = $this->store()->snapshot();

		self::assertReplay( $secondReplay );
		self::assertSame( $terminal->fingerprint(), $idempotent->fingerprint() );
		self::assertSame( 1, $idempotent->codeReplayEventCount() );
	}

	/**
	 * Verifies random invalid input preserves every authoritative domain.
	 *
	 * @since 0.1.0
	 */
	public function testUnknownCodeIsNonRevealingAndPreservesUnrelatedState(): void {
		$this->store()->seedCodeScenario();
		$before = $this->store()->snapshot();

		$result = $this->store()->exchangeUnknownCode();
		$after  = $this->store()->snapshot();

		self::assertSame( TransitionResult::INVALID, $result->status() );
		self::assertTrue( $result->committed() );
		self::assertSame( $before->fingerprint(), $after->fingerprint() );
		self::assertSame( 0, $after->codeReplayEventCount() );
		self::assertSame( $before->unrelatedState(), $after->unrelatedState() );
	}

	/**
	 * Verifies rotation preserves bindings and retired-ancestor replay cascades.
	 *
	 * @since 0.1.0
	 */
	public function testRefreshRotationAndAncestorReplayPreserveBindingsAndContainTheFamily(): void {
		$this->store()->seedRefreshScenario();
		$initial = $this->store()->snapshot();

		$firstRotation = $this->store()->rotateRefresh( 0 );
		$generationOne = $this->store()->snapshot();

		self::assertWinner( $firstRotation );
		self::assertSame( 1, $generationOne->familyCurrentGeneration() );
		self::assertSame( 1, $generationOne->currentRefreshCount() );
		self::assertSame( 3, $generationOne->activeAccessCount() );
		self::assertSame( $initial->bindings(), $generationOne->bindings() );
		self::assertSame( $initial->unrelatedState(), $generationOne->unrelatedState() );

		$secondRotation = $this->store()->rotateRefresh( 1 );
		$generationTwo  = $this->store()->snapshot();

		self::assertWinner( $secondRotation );
		self::assertSame( 2, $generationTwo->familyCurrentGeneration() );
		self::assertSame( 1, $generationTwo->currentRefreshCount() );
		self::assertSame( 4, $generationTwo->activeAccessCount() );
		self::assertSame( $initial->bindings(), $generationTwo->bindings() );

		$ancestorReplay = $this->store()->rotateRefresh( 0 );
		$terminal       = $this->store()->snapshot();

		self::assertReplay( $ancestorReplay );
		self::assertSame( 'compromised', $terminal->familyState() );
		self::assertSame( 'revoked', $terminal->grantState() );
		self::assertSame( 0, $terminal->currentRefreshCount() );
		self::assertSame( 0, $terminal->activeAccessCount() );
		self::assertSame( 1, $terminal->refreshReplayEventCount() );
		self::assertSame( $initial->bindings(), $terminal->bindings() );
		self::assertSame( $initial->unrelatedState(), $terminal->unrelatedState() );

		$idempotentReplay = $this->store()->rotateRefresh( 1 );
		$idempotent       = $this->store()->snapshot();

		self::assertReplay( $idempotentReplay );
		self::assertSame( $terminal->fingerprint(), $idempotent->fingerprint() );
		self::assertSame( 1, $idempotent->refreshReplayEventCount() );
	}

	/**
	 * Verifies every injected pre-commit failure restores prior authority.
	 *
	 * @since 0.1.0
	 *
	 * @dataProvider rollbackPointProvider
	 *
	 * @param string $operation  Fixed lifecycle operation.
	 * @param string $checkpoint Fixed failure checkpoint.
	 */
	public function testInjectedFailureRollsBackTheCompleteTransition(
		string $operation,
		string $checkpoint
	): void {
		$this->prepareOperation( $operation );
		$before = $this->store()->snapshot();

		try {
			$this->runOperation( $operation, new TransitionControl( null, array( $checkpoint ) ) );
			self::fail( 'The injected lifecycle failure unexpectedly returned.' );
		} catch ( TransitionFailure $failure ) {
			self::assertSame( TransitionFailure::INJECTED, $failure->classification() );
		}

		$after = $this->store()->snapshot();

		self::assertSame( $before->fingerprint(), $after->fingerprint() );
		self::assertSame( $before->unrelatedState(), $after->unrelatedState() );
	}

	/**
	 * Verifies commit-response ambiguity becomes fail-closed replay recovery.
	 *
	 * @since 0.1.0
	 */
	public function testCommitAmbiguityDoesNotFinishMissingWritesOrReturnASecondSuccess(): void {
		$this->store()->seedCodeScenario();
		$unrelated = $this->store()->snapshot()->unrelatedState();

		try {
			$this->store()->exchangeCode(
				new TransitionControl( null, array( AtomicLifecycleCheckpoints::AFTER_COMMIT ) )
			);
			self::fail( 'The post-commit response-loss injection unexpectedly returned.' );
		} catch ( TransitionFailure $failure ) {
			self::assertSame( TransitionFailure::INJECTED, $failure->classification() );
		}

		$ambiguous = $this->store()->snapshot();

		self::assertSame( 'consumed', $ambiguous->codeState() );
		self::assertSame( 1, $ambiguous->committedCodeLineageCount() );
		self::assertSame( 3, $ambiguous->validCodeDescendantCount() );
		self::assertSame( 1, $ambiguous->activeAccessCount() );
		self::assertSame( 1, $ambiguous->currentRefreshCount() );

		$retry    = $this->store()->exchangeCode();
		$terminal = $this->store()->snapshot();

		self::assertReplay( $retry );
		self::assertSame( 0, $terminal->activeAccessCount() );
		self::assertSame( 0, $terminal->currentRefreshCount() );
		self::assertSame( 0, $terminal->validCodeDescendantCount() );
		self::assertSame( 1, $terminal->codeReplayEventCount() );
		self::assertSame( $unrelated, $terminal->unrelatedState() );
	}

	/**
	 * Verifies the store exposes no proof credential or digest material.
	 *
	 * @since 0.1.0
	 */
	public function testSanitizedEvidenceContainsOnlyTheFixedSemanticProjection(): void {
		$this->store()->seedRefreshScenario();
		$this->store()->rotateRefresh( 0 );
		$evidence = $this->store()->sanitizedEvidence();

		self::assertSame(
			array(
				'code_state',
				'grant_state',
				'family_state',
				'family_current_generation',
				'committed_code_lineage_count',
				'valid_code_descendant_count',
				'active_access_count',
				'current_refresh_count',
				'code_replay_event_count',
				'refresh_replay_event_count',
				'bindings',
				'unrelated_state',
			),
			array_keys( $evidence )
		);

		// phpcs:ignore WordPress.WP.AlternativeFunctions.json_encode_json_encode -- The standalone proof test does not load WordPress.
		$encoded = json_encode( $evidence, JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES );

		self::assertDoesNotMatchRegularExpression( '/Authorization:|Bearer /i', $encoded );
		self::assertDoesNotMatchRegularExpression( '/credential|digest|token|proof_material/i', $encoded );
		self::assertDoesNotMatchRegularExpression( '/(?<![a-f0-9])[a-f0-9]{64,}(?![a-f0-9])/i', $encoded );
		self::assertDoesNotMatchRegularExpression( '/(?<![A-Za-z0-9+\\/])[A-Za-z0-9+\\/]{80,}={0,2}(?![A-Za-z0-9+\\/])/', $encoded );
	}

	/**
	 * Verifies cleanup removes every disposable proof table.
	 *
	 * @since 0.1.0
	 */
	public function testCleanupDropsOnlyTheDisposableProofSchema(): void {
		AtomicLifecycleSchema::drop( $this->database() );

		self::assertSame(
			array(
				'tables_present'            => false,
				'table_count'               => 0,
				'all_innodb'                => false,
				'unique_invariants_present' => false,
			),
			AtomicLifecycleSchema::capabilities( $this->database() )
		);
	}

	/**
	 * Supplies every mutation-bearing pre-commit injection point.
	 *
	 * @return iterable<string, array{string, string}>
	 */
	public function rollbackPointProvider(): iterable {
		$winnerCheckpoints = array(
			AtomicLifecycleCheckpoints::BEFORE_CLAIM,
			AtomicLifecycleCheckpoints::AFTER_AGGREGATE_LOCK,
			AtomicLifecycleCheckpoints::AFTER_CLAIM,
			AtomicLifecycleCheckpoints::AFTER_DESCENDANT,
			AtomicLifecycleCheckpoints::BEFORE_COMMIT,
		);

		foreach ( $winnerCheckpoints as $checkpoint ) {
			yield 'code winner ' . $checkpoint => array( self::OPERATION_CODE_EXCHANGE, $checkpoint );
			yield 'refresh winner ' . $checkpoint => array( self::OPERATION_REFRESH_ROTATION, $checkpoint );
		}

		foreach ( array( AtomicLifecycleCheckpoints::DURING_REVOKE, AtomicLifecycleCheckpoints::BEFORE_COMMIT ) as $checkpoint ) {
			yield 'code replay ' . $checkpoint => array( self::OPERATION_CODE_REPLAY, $checkpoint );
			yield 'refresh replay ' . $checkpoint => array( self::OPERATION_REFRESH_REPLAY, $checkpoint );
		}
	}

	/**
	 * Seeds the exact precondition for one operation.
	 *
	 * @since 0.1.0
	 *
	 * @param string $operation Fixed lifecycle operation.
	 */
	private function prepareOperation( string $operation ): void {
		switch ( $operation ) {
			case self::OPERATION_CODE_EXCHANGE:
				$this->store()->seedCodeScenario();
				break;
			case self::OPERATION_CODE_REPLAY:
				$this->store()->seedCodeScenario();
				$this->store()->exchangeCode();
				break;
			case self::OPERATION_REFRESH_ROTATION:
				$this->store()->seedRefreshScenario();
				break;
			case self::OPERATION_REFRESH_REPLAY:
				$this->store()->seedRefreshScenario();
				$this->store()->rotateRefresh( 0 );
				break;
			default:
				self::fail( 'Unknown lifecycle operation.' );
		}
	}

	/**
	 * Runs the selected operation behind one transition control.
	 *
	 * @since 0.1.0
	 *
	 * @param string            $operation Fixed lifecycle operation.
	 * @param TransitionControl $control Deterministic transition control.
	 */
	private function runOperation( string $operation, TransitionControl $control ): void {
		switch ( $operation ) {
			case self::OPERATION_CODE_EXCHANGE:
				$this->store()->exchangeCode( $control );
				break;
			case self::OPERATION_CODE_REPLAY:
				$this->store()->exchangeCode( $control );
				break;
			case self::OPERATION_REFRESH_ROTATION:
				$this->store()->rotateRefresh( 0, $control );
				break;
			case self::OPERATION_REFRESH_REPLAY:
				$this->store()->rotateRefresh( 0, $control );
				break;
			default:
				self::fail( 'Unknown lifecycle operation.' );
		}
	}

	/**
	 * Asserts one complete committed winning transition.
	 *
	 * @since 0.1.0
	 *
	 * @param TransitionResult $result Public transition result.
	 */
	private static function assertWinner( TransitionResult $result ): void {
		self::assertSame( TransitionResult::WINNER, $result->status() );
		self::assertTrue( $result->committed() );
		self::assertGreaterThan( 0, $result->connectionId() );
	}

	/**
	 * Asserts one complete committed replay transition.
	 *
	 * @since 0.1.0
	 *
	 * @param TransitionResult $result Public transition result.
	 */
	private static function assertReplay( TransitionResult $result ): void {
		self::assertSame( TransitionResult::REPLAY, $result->status() );
		self::assertTrue( $result->committed() );
		self::assertGreaterThan( 0, $result->connectionId() );
	}

	/**
	 * Returns the initialized public store.
	 *
	 * @since 0.1.0
	 */
	private function store(): AtomicLifecycleStore {
		self::assertInstanceOf( AtomicLifecycleStore::class, $this->store );

		return $this->store;
	}

	/**
	 * Returns the initialized disposable connection.
	 *
	 * @since 0.1.0
	 */
	private function database(): mysqli {
		self::assertInstanceOf( mysqli::class, $this->database );

		return $this->database;
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
}
