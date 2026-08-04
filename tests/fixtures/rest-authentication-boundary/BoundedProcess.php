<?php
/**
 * Bounded child-process execution for the disposable Slice 0 P2 probes.
 *
 * @package GalatanOvidiu\Charter
 */

declare(strict_types=1);

namespace GalatanOvidiu\Charter\Tests\Fixtures\RestAuthenticationBoundary;

/**
 * Runs one child without forwarding its output.
 */
final class BoundedProcess {

	private const MAX_OUTPUT_BYTES = 65536;

	/**
	 * Runs one command with fixed time and output bounds.
	 *
	 * @param array<string> $command         Command and arguments, without shell interpolation.
	 * @param int           $timeout_seconds Timeout from 1 through 60 seconds.
	 * @return array{exit_code: int, timed_out: bool, output_limited: bool, terminated: bool, stdout: string, stderr: string}
	 */
	public static function run( array $command, int $timeout_seconds ): array {
		if ( array() === $command || 1 > $timeout_seconds || 60 < $timeout_seconds ) {
			return self::failure();
		}

		$pipes = array();
		// phpcs:ignore WordPress.PHP.DiscouragedPHPFunctions.system_calls_proc_open -- Independent PHP processes are the proof subject.
		$process = proc_open(
			$command,
			array(
				0 => array( 'pipe', 'r' ),
				1 => array( 'pipe', 'w' ),
				2 => array( 'pipe', 'w' ),
			),
			$pipes,
			null,
			null,
			array( 'bypass_shell' => true )
		);

		if ( ! is_resource( $process ) ) {
			return self::failure();
		}

		// phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_fclose -- Direct pipe ownership is required here.
		fclose( $pipes[0] );
		stream_set_blocking( $pipes[1], false );
		stream_set_blocking( $pipes[2], false );

		$deadline       = microtime( true ) + $timeout_seconds;
		$stdout         = '';
		$stderr         = '';
		$timed_out      = false;
		$output_limited = false;
		$status         = proc_get_status( $process );

		while ( true ) {
			self::appendAvailable( $pipes[1], $stdout );
			self::appendAvailable( $pipes[2], $stderr );

			if ( strlen( $stdout ) + strlen( $stderr ) > self::MAX_OUTPUT_BYTES ) {
				$output_limited = true;
				break;
			}

			$status = proc_get_status( $process );
			if ( ! $status['running'] ) {
				break;
			}

			if ( microtime( true ) >= $deadline ) {
				$timed_out = true;
				break;
			}

			usleep( 10000 );
		}

		if ( $timed_out || $output_limited ) {
			self::terminate( $process );
			$status = proc_get_status( $process );
		}

		self::appendAvailable( $pipes[1], $stdout );
		self::appendAvailable( $pipes[2], $stderr );
		// phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_fclose -- Direct pipe ownership is required here.
		fclose( $pipes[1] );
		// phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_fclose -- Direct pipe ownership is required here.
		fclose( $pipes[2] );

		$observed_exit_code = is_int( $status['exitcode'] ?? null ) ? $status['exitcode'] : -1;
		$closed_exit_code   = proc_close( $process );

		return array(
			'exit_code'      => 0 <= $observed_exit_code ? $observed_exit_code : $closed_exit_code,
			'timed_out'      => $timed_out,
			'output_limited' => $output_limited,
			'terminated'     => ! ( $status['running'] ?? true ),
			'stdout'         => substr( $stdout, 0, self::MAX_OUTPUT_BYTES ),
			'stderr'         => substr( $stderr, 0, self::MAX_OUTPUT_BYTES ),
		);
	}

	/**
	 * Appends currently available bytes from one non-blocking pipe.
	 *
	 * @param resource $pipe   Child pipe.
	 * @param string   $output Accumulated private output.
	 */
	private static function appendAvailable( $pipe, string &$output ): void {
		$chunk = stream_get_contents( $pipe, 8192 );

		if ( false !== $chunk && '' !== $chunk ) {
			$output .= $chunk;
		}
	}

	/**
	 * Terminates a timed-out or over-producing child after a fixed grace period.
	 *
	 * @param resource $process Child process.
	 */
	private static function terminate( $process ): void {
		proc_terminate( $process );
		$deadline = microtime( true ) + 0.5;

		do {
			$status = proc_get_status( $process );
			if ( ! $status['running'] ) {
				return;
			}

			usleep( 10000 );
		} while ( microtime( true ) < $deadline );

		proc_terminate( $process, 9 );
	}

	/**
	 * Returns a fixed internal failure shape.
	 *
	 * @return array{exit_code: int, timed_out: bool, output_limited: bool, terminated: bool, stdout: string, stderr: string}
	 */
	private static function failure(): array {
		return array(
			'exit_code'      => -1,
			'timed_out'      => false,
			'output_limited' => false,
			'terminated'     => true,
			'stdout'         => '',
			'stderr'         => '',
		);
	}
}
