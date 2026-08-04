<?php
/**
 * Orchestrates sanitized fresh-process Slice 0 root-key probes.
 *
 * @package GalatanOvidiu\Charter
 */

declare(strict_types=1);

namespace GalatanOvidiu\Charter\Tests\Fixtures\RootKey;

use Throwable;

require_once __DIR__ . '/ProbeContract.php';

/**
 * Runs workers and exposes only the fixed boolean/status contract.
 */
final class ProbeRunner {

	/**
	 * Runs every phase behind the fixed public failure contract.
	 *
	 * @return array<string, mixed>
	 */
	public static function runSafely(): array {
		try {
			return self::run();
		} catch ( Throwable ) {
			return self::failureResult();
		}
	}

	/**
	 * Runs all fresh-process phases.
	 *
	 * @return array<string, mixed>
	 */
	public static function run(): array {
		$state_file = tempnam( sys_get_temp_dir(), 'charter-slice0-root-key-' );
		if ( false === $state_file ) {
			return self::failureResult();
		}
		// phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_chmod -- Restricts the standalone disposable comparison file.
		chmod( $state_file, 0600 );

		$reset                  = self::runWorker( 'reset', $state_file );
		$initial                = self::runWorker( 'initial', $state_file );
		$firstSibling           = self::runWorker( 'sibling-first', $state_file );
		$secondSibling          = self::runWorker( 'sibling-second', $state_file );
		$reuse                  = self::runWorker( 'reuse', $state_file );
		$explicit               = self::runWorker( 'explicit', $state_file );
		$failureOutputSanitized = self::failureOutputWasSanitized( $state_file );
		$cleanup                = self::runWorker( 'cleanup', $state_file );
		// phpcs:ignore WordPress.WP.AlternativeFunctions.unlink_unlink -- Removes the standalone disposable comparison file.
		unlink( $state_file );

		$fallback        = array(
			'sample_constants_forced_fallback'             => self::check( $initial, 'sample_constants_forced_fallback' ),
			'all_four_schemes_used_network_options'        => self::check( $initial, 'all_four_schemes_used_network_options' ),
			'two_sibling_blogs_shared_effective_values'    => self::check( $firstSibling, 'selected_sibling_read_network_fallback' )
				&& self::check( $secondSibling, 'selected_sibling_read_network_fallback' ),
			'second_fresh_process_reused_persisted_values' => self::check( $reuse, 'second_fresh_process_reused_persisted_values' ),
		);
		$explicit_result = array(
			'selected_before_wordpress_load'           => self::check( $explicit, 'selected_before_wordpress_load' ),
			'stable_after_salt_filter_change'          => self::check( $explicit, 'stable_after_salt_filter_change' ),
			'explicit_credential_survived_salt_change' => self::check( $explicit, 'explicit_credential_survived_salt_change' ),
		);

		$fallback_passed = self::passed( $reset ) && self::passed( $initial )
			&& self::passed( $firstSibling ) && self::passed( $secondSibling ) && self::passed( $reuse )
			&& ! in_array( false, $fallback, true );
		$explicit_passed = self::passed( $explicit ) && ! in_array( false, $explicit_result, true );
		$cleanup_passed  = self::passed( $cleanup ) && self::check( $cleanup, 'cleanup_complete' );

		return array(
			'status'            => $fallback_passed && $explicit_passed && $failureOutputSanitized && $cleanup_passed ? 'passed' : 'failed',
			'fallback'          => array( 'status' => $fallback_passed ? 'passed' : 'failed' ) + $fallback,
			'explicit_override' => array( 'status' => $explicit_passed ? 'passed' : 'failed' ) + $explicit_result,
			'output_safety'     => array(
				'status'                   => $failureOutputSanitized ? 'passed' : 'failed',
				'sanitized_failure_output' => $failureOutputSanitized,
			),
		);
	}

	/**
	 * Runs one worker while discarding all non-contract diagnostics.
	 *
	 * @param string $phase      Probe phase.
	 * @param string $state_file Private temporary comparison-state path.
	 * @return array<string, mixed>
	 */
	private static function runWorker( string $phase, string $state_file ): array {
		$processResult = self::runWorkerProcess( $phase, $state_file );
		$exit_code     = $processResult['exit_code'];
		$stdout        = $processResult['stdout'];

		if ( 0 !== $exit_code || '' === $stdout ) {
			return array();
		}

		return self::decodedWorkerResult( $stdout );
	}

	/**
	 * Proves a marker-bearing worker failure emits only the fixed contract.
	 *
	 * @param string $state_file Private temporary comparison-state path.
	 */
	private static function failureOutputWasSanitized( string $state_file ): bool {
		$processResult = self::runWorkerProcess( 'failure', $state_file );
		$output        = $processResult['stdout'] . $processResult['stderr'];

		foreach ( ProbeContract::FAILURE_OUTPUT_MARKERS as $marker ) {
			if ( str_contains( $output, $marker ) ) {
				return false;
			}
		}

		$result = self::decodedWorkerResult( $processResult['stdout'] );

		return 1 === $processResult['exit_code']
			&& '' === $processResult['stderr']
			&& false === ( $result['passed'] ?? null )
			&& array( 'passed' => false ) === ( $result['checks'] ?? null );
	}

	/**
	 * Runs one worker and retains output only for in-process validation.
	 *
	 * @param string $phase      Probe phase.
	 * @param string $state_file Private temporary comparison-state path.
	 * @return array{exit_code: int, stdout: string, stderr: string}
	 */
	private static function runWorkerProcess( string $phase, string $state_file ): array {
		$command = array( PHP_BINARY, '-d', 'display_errors=0', '-d', 'log_errors=0', __DIR__ . '/ProbeWorker.php', $phase, $state_file );
		$pipes   = array();
		// phpcs:ignore WordPress.PHP.DiscouragedPHPFunctions.system_calls_proc_open -- Fresh PHP processes are the behavior under test.
		$process = proc_open(
			$command,
			array(
				0 => array( 'pipe', 'r' ),
				1 => array( 'pipe', 'w' ),
				2 => array( 'pipe', 'w' ),
			),
			$pipes
		);

		if ( ! is_resource( $process ) ) {
			return array(
				'exit_code' => -1,
				'stdout'    => '',
				'stderr'    => '',
			);
		}

		// phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_fclose -- Direct process-pipe management in a standalone runner.
		fclose( $pipes[0] );
		$stdout = stream_get_contents( $pipes[1] );
		$stderr = stream_get_contents( $pipes[2] );
		// phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_fclose -- Direct process-pipe management in a standalone runner.
		fclose( $pipes[1] );
		// phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_fclose -- Direct process-pipe management in a standalone runner.
		fclose( $pipes[2] );
		$exit_code = proc_close( $process );

		return array(
			'exit_code' => $exit_code,
			'stdout'    => false === $stdout ? '' : $stdout,
			'stderr'    => false === $stderr ? '' : $stderr,
		);
	}

	/**
	 * Decodes one worker's fixed JSON contract.
	 *
	 * @param string $stdout Worker standard output.
	 * @return array<string, mixed>
	 */
	private static function decodedWorkerResult( string $stdout ): array {
		if ( '' === $stdout ) {
			return array();
		}

		try {
			$result = json_decode( $stdout, true, 8, JSON_THROW_ON_ERROR );
		} catch ( Throwable ) {
			return array();
		}

		if ( ! is_array( $result ) ) {
			return array();
		}

		$validated_result = array();

		foreach ( $result as $key => $value ) {
			if ( is_string( $key ) ) {
				$validated_result[ $key ] = $value;
			}
		}

		return $validated_result;
	}

	/**
	 * Checks the worker success marker.
	 *
	 * @param array<string, mixed> $result Worker result.
	 */
	private static function passed( array $result ): bool {
		return true === ( $result['passed'] ?? false );
	}

	/**
	 * Reads one boolean check from a sanitized worker result.
	 *
	 * @param array<string, mixed> $result Worker result.
	 * @param string               $name   Check name.
	 */
	private static function check( array $result, string $name ): bool {
		$checks = $result['checks'] ?? null;

		return is_array( $checks ) && true === ( $checks[ $name ] ?? false );
	}

	/**
	 * Returns the fixed public failure shape.
	 *
	 * @return array<string, mixed>
	 */
	private static function failureResult(): array {
		return array(
			'status'            => 'failed',
			'fallback'          => array(
				'status'                                => 'failed',
				'sample_constants_forced_fallback'      => false,
				'all_four_schemes_used_network_options' => false,
				'two_sibling_blogs_shared_effective_values' => false,
				'second_fresh_process_reused_persisted_values' => false,
			),
			'explicit_override' => array(
				'status'                                   => 'failed',
				'selected_before_wordpress_load'           => false,
				'stable_after_salt_filter_change'          => false,
				'explicit_credential_survived_salt_change' => false,
			),
			'output_safety'     => array(
				'status'                   => 'failed',
				'sanitized_failure_output' => false,
			),
		);
	}
}

$charter_probe_result = ProbeRunner::runSafely();

// phpcs:ignore WordPress.WP.AlternativeFunctions.json_encode_json_encode -- Emits the standalone runner's fixed boolean-only contract.
echo json_encode( $charter_probe_result, JSON_THROW_ON_ERROR );
echo "\n";
exit( 'passed' === $charter_probe_result['status'] ? 0 : 1 );
