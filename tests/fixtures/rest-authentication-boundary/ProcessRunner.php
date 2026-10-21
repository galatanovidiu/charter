<?php
/**
 * Fresh-process and reused-process runner for the disposable Slice 0 P2 proof.
 *
 * Run through `wp eval-file`; emits one fixed boolean-only record.
 *
 * @package GalatanOvidiu\Charter
 */

declare(strict_types=1);

namespace GalatanOvidiu\Charter\Tests\Fixtures\RestAuthenticationBoundary;

use Throwable;

require_once __DIR__ . '/FixtureContract.php';
require_once __DIR__ . '/WorkerContract.php';
require_once __DIR__ . '/BoundedProcess.php';
require_once __DIR__ . '/OwnedProofUsers.php';

/**
 * Runs and validates every child process without forwarding child output.
 */
final class ProcessRunner {

	private const CHILD_TIMEOUT_SECONDS = 20;

	/**
	 * Runs the complete process matrix.
	 *
	 * @param string $run_id Exact disposable run identifier.
	 * @return array<string, mixed>
	 */
	public static function run( string $run_id ): array {
		$users   = new OwnedProofUsers( $run_id );
		$checks  = array();
		$results = array();
		$cleanup = false;

		try {
			$user_ids = $users->create();
			foreach ( WorkerContract::MODES as $mode ) {
				$results[ $mode ] = self::runWorker( $mode, $user_ids['user_a_id'], $user_ids['user_b_id'] );
			}

			$normal_modes = array( 'bearer-only', 'mixed', 'public-mixed', 'error-matrix', 'legacy-only', 'route-matrix', 'direct-served-direct', 'cleanup-matrix', 'reused' );
			$normal       = array_intersect_key( $results, array_flip( $normal_modes ) );
			$failure      = $results['failure-output'];

			$checks = array(
				'wordpress_6_9'                     => FixtureContract::isSupportedWordPressVersion( $GLOBALS['wp_version'] ?? null )
					&& self::allWorkerChecks( $normal, 'wordpress_6_9' ),
				'fresh_bearer_only_succeeded'       => self::workerPassed( $results['bearer-only'] ),
				'fresh_mixed_rejected_400'          => self::workerCheck( $results['mixed'], 'expected_response' ),
				'fresh_mixed_validation_suppressed' => self::workerCheck( $results['mixed'], 'validation_count_exact' ),
				'fresh_mixed_callbacks_suppressed'  => self::workerCheck( $results['mixed'], 'callbacks_exact' ),
				'fresh_mixed_identity_unchanged'    => self::workerCheck( $results['mixed'], 'identity_unchanged' ),
				'fresh_public_mixed_inert'          => self::workerPassed( $results['public-mixed'] ),
				'fresh_error_matrix'                => self::workerPassed( $results['error-matrix'] ),
				'fresh_legacy_only_preserved'       => self::workerPassed( $results['legacy-only'] ),
				'fresh_route_matrix'                => self::workerPassed( $results['route-matrix'] ),
				'fresh_direct_served_direct'        => self::workerPassed( $results['direct-served-direct'] ),
				'fresh_cleanup_matrix'              => self::workerPassed( $results['cleanup-matrix'] ),
				'reused_full_matrix'                => self::workerPassed( $results['reused'] ),
				'context_depth_zero'                => self::allWorkerChecks( $normal, 'context_depth_zero' ),
				'unexpected_output_suppressed'      => self::failureOutputSuppressed( $failure ),
				'all_processes_terminated'          => self::allProcessesTerminated( $results ),
			);
		} finally {
			$cleanup = $users->cleanup();
		}

		$checks['exact_cleanup_complete'] = $cleanup;

		return FixtureContract::processResult( $checks );
	}

	/**
	 * Runs one fresh WP-CLI process and privately decodes its contract.
	 *
	 * @param string $mode      Worker mode.
	 * @param int    $user_a_id Bearer user.
	 * @param int    $user_b_id Legacy user.
	 * @return array{process: array{exit_code: int, timed_out: bool, output_limited: bool, terminated: bool, stdout: string, stderr: string}, result: array<string, mixed>}
	 */
	private static function runWorker( string $mode, int $user_a_id, int $user_b_id ): array {
		$process = BoundedProcess::run(
			array(
				'env',
				'CHARTER_P2_MODE=' . $mode,
				'CHARTER_P2_USER_A_ID=' . $user_a_id,
				'CHARTER_P2_USER_B_ID=' . $user_b_id,
				'CHARTER_P2_WORKER_PATH=' . __DIR__ . '/ProcessWorker.php',
				'wp',
				'--quiet',
				'--url=' . home_url( '/' ),
				'eval',
				'$args = array( (string) getenv( "CHARTER_P2_MODE" ), (string) getenv( "CHARTER_P2_USER_A_ID" ), (string) getenv( "CHARTER_P2_USER_B_ID" ) ); require (string) getenv( "CHARTER_P2_WORKER_PATH" );',
			),
			self::CHILD_TIMEOUT_SECONDS
		);

		$result = array();
		if ( '' !== $process['stdout'] ) {
			try {
				$decoded = json_decode( trim( $process['stdout'] ), true, 8, JSON_THROW_ON_ERROR );
				if ( WorkerContract::isResult( $decoded, $mode ) ) {
					$result = $decoded;
				}
			} catch ( Throwable ) {
				$result = array();
			}
		}

		return array(
			'process' => $process,
			'result'  => $result,
		);
	}

	/**
	 * Checks whether one ordinary worker passed cleanly.
	 *
	 * @param array<string, mixed> $worker Worker envelope.
	 */
	private static function workerPassed( array $worker ): bool {
		return 0 === ( $worker['process']['exit_code'] ?? null )
			&& '' === ( $worker['process']['stderr'] ?? null )
			&& true === ( $worker['result']['passed'] ?? null );
	}

	/**
	 * Reads one boolean from a validated worker.
	 *
	 * @param array<string, mixed> $worker Worker envelope.
	 * @param string               $key    Check key.
	 */
	private static function workerCheck( array $worker, string $key ): bool {
		return self::workerPassed( $worker ) && true === ( $worker['result']['checks'][ $key ] ?? false );
	}

	/**
	 * Checks one key across every normal worker.
	 *
	 * @param array<string, array<string, mixed>> $workers Worker envelopes.
	 * @param string                              $key     Check key.
	 */
	private static function allWorkerChecks( array $workers, string $key ): bool {
		foreach ( $workers as $worker ) {
			if ( ! self::workerCheck( $worker, $key ) ) {
				return false;
			}
		}

		return array() !== $workers;
	}

	/**
	 * Proves a marker-bearing worker failure emitted no detail.
	 *
	 * @param array<string, mixed> $worker Failure worker envelope.
	 */
	private static function failureOutputSuppressed( array $worker ): bool {
		$output = (string) ( $worker['process']['stdout'] ?? '' ) . (string) ( $worker['process']['stderr'] ?? '' );

		foreach ( WorkerContract::PRIVATE_FAILURE_MARKERS as $marker ) {
			if ( str_contains( $output, $marker ) ) {
				return false;
			}
		}

		return 1 === ( $worker['process']['exit_code'] ?? null )
			&& '' === ( $worker['process']['stderr'] ?? null )
			&& false === ( $worker['result']['passed'] ?? null );
	}

	/**
	 * Checks that every child reached a non-running state without a timeout.
	 *
	 * @param array<string, array<string, mixed>> $workers Worker envelopes.
	 */
	private static function allProcessesTerminated( array $workers ): bool {
		foreach ( $workers as $worker ) {
			if (
				true !== ( $worker['process']['terminated'] ?? false )
				|| true === ( $worker['process']['timed_out'] ?? true )
				|| true === ( $worker['process']['output_limited'] ?? true )
			) {
				return false;
			}
		}

		return count( WorkerContract::MODES ) === count( $workers );
	}

	/**
	 * Prevents construction.
	 */
	private function __construct() {}
}

$charter_p2_runner_args = isset( $args ) && is_array( $args ) ? $args : array();
$charter_p2_runner_id   = is_string( $charter_p2_runner_args[0] ?? null ) ? $charter_p2_runner_args[0] : '';

try {
	$charter_p2_runner_result = ProcessRunner::run( $charter_p2_runner_id );
} catch ( Throwable ) {
	$charter_p2_runner_result = FixtureContract::processFailure();
}

// phpcs:ignore WordPress.WP.AlternativeFunctions.json_encode_json_encode -- Emits one public fixed boolean-only runner record.
echo json_encode( $charter_p2_runner_result, JSON_THROW_ON_ERROR );
echo "\n";
exit( $charter_p2_runner_result['passed'] ? 0 : 1 );
