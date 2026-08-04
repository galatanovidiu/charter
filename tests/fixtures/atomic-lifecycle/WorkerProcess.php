<?php
/**
 * Bounded process wrapper for one independent P1 database worker.
 *
 * @package GalatanOvidiu\Charter
 */

declare(strict_types=1);

namespace GalatanOvidiu\Charter\Tests\Fixtures\AtomicLifecycle;

// phpcs:disable Generic.Commenting.DocComment.MissingShort, Squiz.Commenting -- Standalone proof-process internals are described at their public seams.

use RuntimeException;
use Throwable;

/**
 * Exchanges only fixed NDJSON protocol messages with one PHP child process.
 */
final class WorkerProcess {

	private static int $activeProcesses = 0;

	/** @var resource|null */
	private $process = null;

	/** @var array<int, resource> */
	private array $pipes = array();

	private string $stdoutBuffer = '';

	private bool $stderrObserved = false;

	private bool $closed = false;

	private bool $countedActive = false;

	private ?int $connectionId = null;

	private ?int $observedExitCode = null;

	/** @var list<array<string, mixed>> */
	private array $messageQueue = array();

	/**
	 * @param int $workerId Worker sequence number.
	 * @param int $timeout  Per-wait timeout in seconds.
	 */
	public function __construct(
		private readonly int $workerId,
		private readonly int $timeout = HarnessContract::DEFAULT_WORKER_TIMEOUT_SECONDS
	) {
		if ( 0 > $workerId || 1 > $timeout || HarnessContract::MAXIMUM_WORKER_TIMEOUT_SECONDS < $timeout ) {
			throw new RuntimeException( 'Invalid worker process bound.' );
		}
	}

	public function __destruct() {
		$this->close();
	}

	/**
	 * Starts the worker and waits for its sanitized ready message.
	 *
	 * @return array<string, mixed>
	 */
	public function start(): array {
		if ( is_resource( $this->process ) ) {
			throw new RuntimeException( 'Worker process already started.' );
		}

		$command = array(
			PHP_BINARY,
			'-d',
			'display_errors=0',
			'-d',
			'log_errors=0',
			__DIR__ . '/AtomicLifecycleWorker.php',
			(string) $this->workerId,
		);
		$pipes   = array();

		// phpcs:ignore WordPress.PHP.DiscouragedPHPFunctions.system_calls_proc_open -- Separate PHP processes and database connections are the behavior under test.
		$process = proc_open(
			$command,
			array(
				0 => array( 'pipe', 'r' ),
				1 => array( 'pipe', 'w' ),
				2 => array( 'pipe', 'w' ),
			),
			$pipes
		);

		if ( ! is_resource( $process ) || 3 !== count( $pipes ) ) {
			throw new RuntimeException( 'Worker process could not start.' );
		}

		$this->process       = $process;
		$this->pipes         = $pipes;
		$this->countedActive = true;
		++self::$activeProcesses;
		stream_set_blocking( $this->pipes[1], false );
		stream_set_blocking( $this->pipes[2], false );

		$message      = $this->waitForType( HarnessContract::MESSAGE_READY );
		$connectionId = $message['connection_id'] ?? null;

		if ( ! is_int( $connectionId ) || 1 > $connectionId ) {
			throw new RuntimeException( 'Worker did not report a valid connection identity.' );
		}

		if ( true !== ( $message['wordpress_loaded'] ?? null ) || false !== ( $message['database_drop_in_loaded'] ?? null ) ) {
			throw new RuntimeException( 'Worker did not prove the exact WordPress database boundary.' );
		}

		$this->connectionId = $connectionId;

		return $message;
	}

	/**
	 * Sends a fixed command to the worker.
	 *
	 * @param array<string, bool|int|string|list<string>> $command Command message.
	 */
	public function send( array $command ): void {
		if ( ! isset( $this->pipes[0] ) || ! is_resource( $this->pipes[0] ) ) {
			throw new RuntimeException( 'Worker command pipe is unavailable.' );
		}

		try {
			// phpcs:ignore WordPress.WP.AlternativeFunctions.json_encode_json_encode -- WordPress is intentionally not loaded in the standalone worker coordinator.
			$encoded = json_encode( $command, JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES );
		} catch ( Throwable ) {
			throw new RuntimeException( 'Worker command could not be encoded.' );
		}

		// phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_fwrite -- Writes a fixed protocol command to a child-process pipe.
		$written = fwrite( $this->pipes[0], $encoded . "\n" );
		if ( false === $written || strlen( $encoded ) + 1 !== $written ) {
			throw new RuntimeException( 'Worker command could not be written.' );
		}

		fflush( $this->pipes[0] );
	}

	/**
	 * Waits for one message of the requested type and optional checkpoint.
	 *
	 * @return array<string, mixed>
	 */
	public function waitForType( string $type, ?string $checkpoint = null ): array {
		$deadline = microtime( true ) + $this->timeout;

		while ( microtime( true ) < $deadline ) {
			foreach ( $this->readAvailableMessages( $deadline ) as $newMessage ) {
				$this->messageQueue[] = $newMessage;
			}

			foreach ( $this->messageQueue as $index => $message ) {
				if (
					( $message['type'] ?? null ) === $type
					&& ( null === $checkpoint || ( $message['checkpoint'] ?? null ) === $checkpoint )
				) {
					array_splice( $this->messageQueue, $index, 1 );
					return $message;
				}
			}

			if ( ! $this->isRunning() && '' === $this->stdoutBuffer ) {
				break;
			}
		}

		throw new RuntimeException( 'Worker did not satisfy the bounded protocol wait.' );
	}

	/**
	 * Waits until a held checkpoint is reached or the worker fails beforehand.
	 *
	 * @return array<string, mixed>
	 */
	public function waitForCheckpointOrResult( string $checkpoint ): array {
		$deadline = microtime( true ) + $this->timeout;

		while ( microtime( true ) < $deadline ) {
			foreach ( $this->readAvailableMessages( $deadline ) as $newMessage ) {
				$this->messageQueue[] = $newMessage;
			}

			foreach ( $this->messageQueue as $index => $message ) {
				$isCheckpoint = HarnessContract::MESSAGE_CHECKPOINT === ( $message['type'] ?? null )
					&& ( $message['checkpoint'] ?? null ) === $checkpoint;
				$isResult     = HarnessContract::MESSAGE_RESULT === ( $message['type'] ?? null );

				if ( $isCheckpoint || $isResult ) {
					array_splice( $this->messageQueue, $index, 1 );
					return $message;
				}
			}

			if ( ! $this->isRunning() && '' === $this->stdoutBuffer ) {
				break;
			}
		}

		throw new RuntimeException( 'Worker did not reach its checkpoint or return a result.' );
	}

	/**
	 * Releases one deterministic worker checkpoint.
	 */
	public function release( string $checkpoint ): void {
		$this->send(
			array(
				'command'    => HarnessContract::COMMAND_RELEASE,
				'checkpoint' => $checkpoint,
			)
		);
	}

	/**
	 * Returns the sanitized ready connection identifier.
	 */
	public function connectionId(): int {
		if ( null === $this->connectionId ) {
			throw new RuntimeException( 'Worker did not report a valid connection identity.' );
		}

		return $this->connectionId;
	}

	/**
	 * Closes pipes before reaping the process, with bounded termination.
	 */
	public function close(): int {
		if ( $this->closed ) {
			return -1;
		}

		$this->closed = true;
		if ( isset( $this->pipes[0] ) && is_resource( $this->pipes[0] ) ) {
			// phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_fclose -- Direct child-process pipe management.
			fclose( $this->pipes[0] );
		}

		$deadline = microtime( true ) + 1.0;
		while ( $this->isRunning() && microtime( true ) < $deadline ) {
			$this->readAvailableMessages( $deadline );
		}

		if ( $this->isRunning() && is_resource( $this->process ) ) {
			// phpcs:ignore WordPress.PHP.DiscouragedPHPFunctions.system_calls_proc_terminate -- Terminates only this runner-owned bounded child.
			proc_terminate( $this->process );
		}

		foreach ( array( 1, 2 ) as $pipeIndex ) {
			if ( isset( $this->pipes[ $pipeIndex ] ) && is_resource( $this->pipes[ $pipeIndex ] ) ) {
				// phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_fclose -- Direct child-process pipe management.
				fclose( $this->pipes[ $pipeIndex ] );
			}
		}

		$exitCode = $this->observedExitCode ?? -1;
		if ( is_resource( $this->process ) ) {
			$closedExitCode = proc_close( $this->process );
			if ( 0 <= $closedExitCode ) {
				$exitCode = $closedExitCode;
			}
		}

		$this->pipes   = array();
		$this->process = null;
		if ( $this->countedActive ) {
			$this->countedActive = false;
			--self::$activeProcesses;
		}

		return $this->stderrObserved ? -1 : $exitCode;
	}

	/**
	 * Returns the coordinator-owned count of unreaped child processes.
	 */
	public static function activeCount(): int {
		return self::$activeProcesses;
	}

	/**
	 * Whether the child is still running.
	 */
	public function isRunning(): bool {
		if ( ! is_resource( $this->process ) ) {
			return false;
		}

		$status = proc_get_status( $this->process );
		if ( false === $status['running'] && 0 <= $status['exitcode'] ) {
			$this->observedExitCode = $status['exitcode'];
		}

		return $status['running'];
	}

	/**
	 * Reads, validates, and returns complete NDJSON messages.
	 *
	 * @return list<array<string, mixed>>
	 */
	private function readAvailableMessages( float $deadline ): array {
		if ( ! isset( $this->pipes[1], $this->pipes[2] ) ) {
			return array();
		}

		$read = array();
		foreach ( array( 1, 2 ) as $pipeIndex ) {
			if ( is_resource( $this->pipes[ $pipeIndex ] ) && ! feof( $this->pipes[ $pipeIndex ] ) ) {
				$read[] = $this->pipes[ $pipeIndex ];
			}
		}

		if ( array() !== $read ) {
			$write  = null;
			$except = null;
			$usec   = (int) min( 200000, max( 0, ( $deadline - microtime( true ) ) * 1000000 ) );
			$ready  = stream_select( $read, $write, $except, 0, $usec );

			if ( false === $ready ) {
				throw new RuntimeException( 'Worker protocol select failed.' );
			}

			foreach ( $read as $stream ) {
				// phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_fread -- Reads a bounded child-process pipe.
				$chunk = fread( $stream, 8192 );
				if ( false === $chunk || '' === $chunk ) {
					continue;
				}

				if ( $stream === $this->pipes[2] ) {
					$this->stderrObserved = true;
					continue;
				}

				$this->stdoutBuffer .= $chunk;
				if ( 65536 < strlen( $this->stdoutBuffer ) ) {
					throw new RuntimeException( 'Worker protocol output exceeded its bound.' );
				}
			}
		}

		$messages = array();
		$newline  = strpos( $this->stdoutBuffer, "\n" );
		while ( false !== $newline ) {
			$line               = substr( $this->stdoutBuffer, 0, $newline );
			$this->stdoutBuffer = substr( $this->stdoutBuffer, $newline + 1 );

			if ( '' === $line ) {
				continue;
			}

			try {
				$message = json_decode( $line, true, 8, JSON_THROW_ON_ERROR );
			} catch ( Throwable ) {
				throw new RuntimeException( 'Worker protocol output was invalid.' );
			}

			if ( ! is_array( $message ) || ! self::messageIsSafe( $message ) ) {
				throw new RuntimeException( 'Worker protocol output violated its fixed schema.' );
			}

			$validatedMessage = array();
			foreach ( $message as $key => $value ) {
				if ( is_string( $key ) ) {
					$validatedMessage[ $key ] = $value;
				}
			}

			$messages[] = $validatedMessage;
			$newline    = strpos( $this->stdoutBuffer, "\n" );
		}

		return $messages;
	}

	/**
	 * Validates worker messages before returning any field to the coordinator.
	 *
	 * @param array<array-key, mixed> $message Candidate protocol message.
	 */
	private static function messageIsSafe( array $message ): bool {
		if ( ! isset( $message['type'] ) || ! is_string( $message['type'] ) ) {
			return false;
		}

		if ( ! in_array( $message['type'], array( HarnessContract::MESSAGE_READY, HarnessContract::MESSAGE_CHECKPOINT, HarnessContract::MESSAGE_RESULT ), true ) ) {
			return false;
		}

		try {
			// phpcs:ignore WordPress.WP.AlternativeFunctions.json_encode_json_encode -- WordPress is intentionally not loaded in the standalone worker coordinator.
			$encoded = json_encode( $message, JSON_THROW_ON_ERROR );
		} catch ( Throwable ) {
			return false;
		}

		if ( 4096 < strlen( $encoded ) ) {
			return false;
		}

		if ( preg_match( '/(?<![a-f0-9])[a-f0-9]{64,}(?![a-f0-9])/i', $encoded ) ) {
			return false;
		}

		return ! str_contains( $encoded, 'Authorization:' ) && ! str_contains( $encoded, 'Bearer ' );
	}
}
