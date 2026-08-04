<?php
/**
 * Fixed-output runner for one disposable Slice 0 P1 database lane.
 *
 * @package GalatanOvidiu\Charter
 */

declare(strict_types=1);

namespace GalatanOvidiu\Charter\Tests\Fixtures\AtomicLifecycle;

// phpcs:disable Generic.Commenting.DocComment.MissingShort, Squiz.Commenting -- Standalone runner internals are constrained by the fixed output contract.
// phpcs:disable WordPress.Security.EscapeOutput.OutputNotEscaped -- SanitizedResult is the escaping and output-validation boundary.

use RuntimeException;
use Throwable;

require_once __DIR__ . '/AtomicLifecycleHarness.php';

/**
 * Creates, exercises, and cleans one already-provisioned database lane.
 */
final class AtomicLifecycleLaneRunner {

	/**
	 * Executes the requested mode.
	 */
	public static function run( string $mode ): int {
		return match ( $mode ) {
			'wait' => self::waitForDatabase(),
			'run'  => self::runLane(),
			default => throw new RuntimeException( 'Unknown atomic-lifecycle lane mode.' ),
		};
	}

	private static function waitForDatabase(): int {
		$timeout  = HarnessContract::boundedEnvironmentInteger( 'CHARTER_ATOMIC_READY_TIMEOUT', 120, 1, 300 );
		$deadline = microtime( true ) + $timeout;

		do {
			try {
				$connection = LaneConfiguration::fromEnvironment()->connect();
				$connection->close();

				return 0;
			} catch ( Throwable ) {
				usleep( 250000 );
			}
		} while ( microtime( true ) < $deadline );

		return 1;
	}

	private static function runLane(): int {
		$lane        = LaneConfiguration::fromEnvironment();
		$workers     = HarnessContract::boundedEnvironmentInteger(
			'CHARTER_ATOMIC_WORKERS',
			HarnessContract::DEFAULT_WORKERS,
			HarnessContract::MINIMUM_DECISIVE_WORKERS,
			HarnessContract::MAXIMUM_WORKERS
		);
		$rounds      = HarnessContract::boundedEnvironmentInteger(
			'CHARTER_ATOMIC_ROUNDS',
			HarnessContract::DEFAULT_ROUNDS,
			HarnessContract::MINIMUM_DECISIVE_ROUNDS,
			HarnessContract::MAXIMUM_ROUNDS
		);
		$laneTimeout = HarnessContract::boundedEnvironmentInteger(
			'CHARTER_ATOMIC_LANE_TIMEOUT',
			HarnessContract::DEFAULT_LANE_TIMEOUT_SECONDS,
			60,
			HarnessContract::MAXIMUM_LANE_TIMEOUT_SECONDS
		);
		$deadline    = microtime( true ) + $laneTimeout;
		$passed      = true;
		$created     = false;

		try {
			AtomicLifecycleHarness::createFixture( $lane );
			$created = true;

			foreach ( HarnessContract::cases() as $caseId ) {
				if ( microtime( true ) >= $deadline ) {
					$passed = false;
					break;
				}

				$result = AtomicLifecycleHarness::runCase( $caseId, $lane, $workers, $rounds );
				self::emit( $result );

				if ( true !== ( $result['passed'] ?? false ) ) {
					$passed = false;
					break;
				}
			}
		} catch ( Throwable ) {
			$passed = false;
			self::emit( SanitizedResult::base( $lane, HarnessContract::CASE_PREFLIGHT, $workers, 1 ) );
		} finally {
			try {
				AtomicLifecycleHarness::dropFixture( $lane );
			} catch ( Throwable ) {
				$passed = false;
			}
		}

		$remaining                             = AtomicLifecycleHarness::cleanupTablesRemaining( $lane );
		$cleanup                               = SanitizedResult::base( $lane, HarnessContract::CASE_CLEANUP, 0, 1 );
		$cleanup['cleanup_tables_remaining']   = $remaining;
		$cleanup['worker_processes_remaining'] = 0;
		$cleanup['outcomes']                   = array( 0 === $remaining ? HarnessContract::OUTCOME_PASSED : HarnessContract::OUTCOME_FAILED );
		$cleanup['status']                     = $created && 0 === $remaining ? HarnessContract::OUTCOME_PASSED : HarnessContract::OUTCOME_FAILED;
		$cleanup['passed']                     = $created && 0 === $remaining;
		self::emit( $cleanup );

		return $passed && true === $cleanup['passed'] ? 0 : 1;
	}

	/**
	 * @param array<string, mixed> $result Fixed result.
	 */
	private static function emit( array $result ): void {
		echo SanitizedResult::encode( $result ) . "\n";
		flush();
	}
}

try {
	$charter_atomic_mode = $argv[1] ?? 'run';
	exit( AtomicLifecycleLaneRunner::run( $charter_atomic_mode ) );
} catch ( Throwable ) {
	echo SanitizedResult::encode( SanitizedResult::opaqueFailure() ) . "\n";
	exit( 1 );
}
