<?php
/**
 * Independent database worker for the disposable Slice 0 P1 harness.
 *
 * @package GalatanOvidiu\Charter
 */

declare(strict_types=1);

namespace GalatanOvidiu\Charter\Tests\Fixtures\AtomicLifecycle;

// phpcs:disable Generic.Commenting.DocComment.MissingShort, Squiz.Commenting -- Standalone worker internals are constrained by the fixed protocol.
// phpcs:disable WordPress.Security.EscapeOutput.OutputNotEscaped -- Every emitted value is fixed-schema coordinator protocol data.

use GalatanOvidiu\Charter\Tests\Prototype\AtomicLifecycle\AtomicLifecycleCheckpoints;
use GalatanOvidiu\Charter\Tests\Prototype\AtomicLifecycle\AtomicLifecycleStore;
use GalatanOvidiu\Charter\Tests\Prototype\AtomicLifecycle\TransitionControl;
use GalatanOvidiu\Charter\Tests\Prototype\AtomicLifecycle\TransitionFailure;
use GalatanOvidiu\Charter\Tests\Prototype\AtomicLifecycle\TransitionResult;
use RuntimeException;
use Throwable;

require_once dirname( __DIR__, 3 ) . '/vendor/autoload.php';
require_once __DIR__ . '/HarnessContract.php';
require_once __DIR__ . '/LaneConfiguration.php';
require_once __DIR__ . '/RawWpdbReconnectProbe.php';
require_once __DIR__ . '/WordPressWorkerBootstrap.php';

/**
 * Accepts one fixed operation and exposes only checkpoint/result messages.
 */
final class AtomicLifecycleWorker {

	/** @var resource */
	private $input;

	private readonly LaneConfiguration $lane;

	private readonly AtomicLifecycleStore $store;

	private readonly int $workerId;

	private readonly int $connectionId;

	/**
	 * @param int $workerId Fixed coordinator worker number.
	 */
	public function __construct( int $workerId ) {
		if ( 0 > $workerId || HarnessContract::MAXIMUM_WORKERS <= $workerId ) {
			throw new RuntimeException( 'Invalid worker number.' );
		}

		$this->workerId = $workerId;
		$this->input    = STDIN;
		$this->lane     = LaneConfiguration::fromEnvironment();
		WordPressWorkerBootstrap::load( $this->lane );
		$database   = $this->lane->connect();
		$timeoutSet = $database->query(
			'SET SESSION innodb_lock_wait_timeout = ' . HarnessContract::DEFAULT_LOCK_WAIT_TIMEOUT_SECONDS
		);
		if ( true !== $timeoutSet ) {
			throw new RuntimeException( 'Session lock timeout could not be set.' );
		}
		$this->store        = new AtomicLifecycleStore( $database );
		$this->connectionId = $this->store->connectionId();
	}

	/**
	 * Runs one worker operation.
	 */
	public function run(): int {
		$this->emit(
			array(
				'type'                    => HarnessContract::MESSAGE_READY,
				'protocol'                => HarnessContract::PROTOCOL_VERSION,
				'worker_id'               => $this->workerId,
				'connection_id'           => $this->connectionId,
				'wordpress_loaded'        => true,
				'database_drop_in_loaded' => false,
			)
		);

		$command = $this->readCommand();
		if ( HarnessContract::COMMAND_STOP === ( $command['command'] ?? null ) ) {
			return 0;
		}

		if ( HarnessContract::COMMAND_RUN !== ( $command['command'] ?? null ) ) {
			throw new RuntimeException( 'Unexpected worker command.' );
		}

		$action  = self::requiredString( $command, 'action' );
		$holdAt  = self::stringList( $command, 'hold_at' );
		$failAt  = self::stringList( $command, 'fail_at' );
		$exitAt  = self::optionalString( $command, 'exit_at' );
		$control = new TransitionControl(
			function ( string $checkpoint, int $connectionId ) use ( $holdAt, $exitAt ): void {
				$this->checkpoint( $checkpoint, $connectionId, in_array( $checkpoint, $holdAt, true ) );

				if ( $exitAt === $checkpoint ) {
					exit( HarnessContract::WORKER_EXIT_EXPECTED_DEATH );
				}
			},
			$failAt
		);

		try {
			$result = $this->execute( $action, $command, $control );
			$this->emitResult(
				$result->status(),
				$result->committed(),
				$result->connectionId(),
				null,
				null,
				false
			);

			return 0;
		} catch ( TransitionFailure $failure ) {
			$this->emitResult(
				$failure->classification(),
				false,
				$failure->connectionId() ?? $this->connectionId,
				$failure->databaseErrorNumber(),
				$failure->sqlStateClass(),
				false
			);

			return 0;
		}
	}

	/**
	 * @param string               $action  Fixed action.
	 * @param array<string, mixed> $command Fixed command.
	 */
	private function execute( string $action, array $command, TransitionControl $control ): TransitionResult {
		if ( HarnessContract::ACTION_RAW_WPDB_CONNECTION_LOSS === $action ) {
			try {
				$probe = RawWpdbReconnectProbe::run(
					$this->lane,
					function ( string $checkpoint, int $connectionId ): void {
						$this->checkpoint( $checkpoint, $connectionId, true );
					}
				);
			} catch ( Throwable ) {
				$this->emitResult(
					HarnessContract::OUTCOME_FAILED,
					false,
					$this->connectionId,
					null,
					null,
					false
				);

				exit( 0 );
			}

			$this->emitResult(
				HarnessContract::OUTCOME_CONNECTION_LOST,
				false,
				$probe['connection_id'],
				2006,
				'08',
				$probe['replayed_outside_transaction']
			);

			exit( 0 );
		}

		return match ( $action ) {
			HarnessContract::ACTION_SEED_CODE => $this->seedCodeScenario(),
			HarnessContract::ACTION_SEED_REFRESH => $this->seedRefreshScenario(),
			HarnessContract::ACTION_EXCHANGE_CODE => $this->store->exchangeCode( $control ),
			HarnessContract::ACTION_EXCHANGE_UNKNOWN_CODE => $this->store->exchangeUnknownCode( $control ),
			HarnessContract::ACTION_ROTATE_REFRESH => $this->store->rotateRefresh(
				self::requiredInteger( $command, 'generation' ),
				$control
			),
			HarnessContract::ACTION_SENTINEL => $this->runSentinel( $command, $control ),
			HarnessContract::ACTION_CONNECTION_LOSS => $this->store->connectionLossTransition( $control ),
			default => throw new RuntimeException( 'Unknown worker action.' ),
		};
	}

	private function seedCodeScenario(): TransitionResult {
		$this->store->seedCodeScenario();

		return new TransitionResult(
			HarnessContract::OUTCOME_WINNER,
			true,
			$this->store->connectionId()
		);
	}

	private function seedRefreshScenario(): TransitionResult {
		$this->store->seedRefreshScenario();

		return new TransitionResult(
			HarnessContract::OUTCOME_WINNER,
			true,
			$this->store->connectionId()
		);
	}

	/**
	 * @param array<string, mixed> $command Fixed command.
	 */
	private function runSentinel( array $command, TransitionControl $control ): TransitionResult {
		$timeout = self::requiredInteger( $command, 'lock_wait_timeout' );

		if ( 1 > $timeout || 10 < $timeout ) {
			throw new RuntimeException( 'Invalid session lock timeout.' );
		}

		if ( HarnessContract::DEFAULT_LOCK_WAIT_TIMEOUT_SECONDS !== $timeout ) {
			throw new RuntimeException( 'Unexpected fixed session lock timeout.' );
		}

		return $this->store->exerciseSentinelTransition(
			self::requiredInteger( $command, 'first_sentinel' ),
			self::requiredInteger( $command, 'second_sentinel' ),
			$control
		);
	}

	private function checkpoint( string $checkpoint, int $connectionId, bool $hold ): void {
		$this->emit(
			array(
				'type'          => HarnessContract::MESSAGE_CHECKPOINT,
				'protocol'      => HarnessContract::PROTOCOL_VERSION,
				'worker_id'     => $this->workerId,
				'checkpoint'    => $checkpoint,
				'connection_id' => $connectionId,
			)
		);

		if ( ! $hold ) {
			return;
		}

		$release = $this->readCommand();
		if (
			HarnessContract::COMMAND_RELEASE !== ( $release['command'] ?? null )
			|| ( $release['checkpoint'] ?? null ) !== $checkpoint
		) {
			throw new RuntimeException( 'Checkpoint release did not match.' );
		}
	}

	private function emitResult(
		string $outcome,
		bool $committed,
		int $connectionId,
		?int $errorNumber,
		?string $sqlStateClass,
		bool $rawWpdbReplayed
	): void {
		$this->emit(
			array(
				'type'                                  => HarnessContract::MESSAGE_RESULT,
				'protocol'                              => HarnessContract::PROTOCOL_VERSION,
				'worker_id'                             => $this->workerId,
				'outcome'                               => $outcome,
				'committed'                             => $committed,
				'connection_id'                         => $connectionId,
				'error_number'                          => $errorNumber,
				'sqlstate_class'                        => $sqlStateClass,
				'raw_wpdb_replayed_outside_transaction' => $rawWpdbReplayed,
			)
		);
	}

	/**
	 * @return array<string, mixed>
	 */
	private function readCommand(): array {
		$line = fgets( $this->input, 4097 );
		if ( false === $line || 4096 < strlen( $line ) ) {
			throw new RuntimeException( 'Worker protocol command was unavailable.' );
		}

		try {
			$command = json_decode( trim( $line ), true, 8, JSON_THROW_ON_ERROR );
		} catch ( Throwable ) {
			throw new RuntimeException( 'Worker protocol command was invalid.' );
		}

		if ( ! is_array( $command ) ) {
			throw new RuntimeException( 'Worker protocol command was not an object.' );
		}

		$validatedCommand = array();
		foreach ( $command as $key => $value ) {
			if ( is_string( $key ) ) {
				$validatedCommand[ $key ] = $value;
			}
		}

		return $validatedCommand;
	}

	/**
	 * @param array<string, mixed> $message Fixed protocol message.
	 */
	private function emit( array $message ): void {
		try {
			// phpcs:ignore WordPress.WP.AlternativeFunctions.json_encode_json_encode -- WordPress is intentionally absent from this standalone process.
			$encoded = json_encode( $message, JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES );
		} catch ( Throwable ) {
			exit( HarnessContract::WORKER_EXIT_PROTOCOL_FAILURE );
		}

		echo $encoded . "\n";
		flush();
	}

	/**
	 * @param array<string, mixed> $command Command.
	 */
	private static function requiredString( array $command, string $key ): string {
		$value = $command[ $key ] ?? null;

		if ( ! is_string( $value ) || '' === $value ) {
			throw new RuntimeException( 'Required worker string was invalid.' );
		}

		return $value;
	}

	/**
	 * @param array<string, mixed> $command Command.
	 */
	private static function optionalString( array $command, string $key ): ?string {
		$value = $command[ $key ] ?? null;

		if ( null !== $value && ! is_string( $value ) ) {
			throw new RuntimeException( 'Optional worker string was invalid.' );
		}

		return $value;
	}

	/**
	 * @param array<string, mixed> $command Command.
	 */
	private static function requiredInteger( array $command, string $key ): int {
		$value = $command[ $key ] ?? null;

		if ( ! is_int( $value ) ) {
			throw new RuntimeException( 'Required worker integer was invalid.' );
		}

		return $value;
	}

	/**
	 * @param array<string, mixed> $command Command.
	 * @return list<string>
	 */
	private static function stringList( array $command, string $key ): array {
		$value = $command[ $key ] ?? array();

		if ( ! is_array( $value ) || ! array_is_list( $value ) ) {
			throw new RuntimeException( 'Worker string list was invalid.' );
		}

		foreach ( $value as $item ) {
			if ( ! is_string( $item ) ) {
				throw new RuntimeException( 'Worker string-list item was invalid.' );
			}
		}

		return $value;
	}
}

try {
	$charter_atomic_worker_id = isset( $argv[1] ) && ctype_digit( $argv[1] ) ? (int) $argv[1] : -1;
	$charter_atomic_worker    = new AtomicLifecycleWorker( $charter_atomic_worker_id );
	exit( $charter_atomic_worker->run() );
} catch ( Throwable ) {
	echo '{"type":"result","protocol":1,"worker_id":0,"outcome":"failed","committed":false,"connection_id":0,"error_number":null,"sqlstate_class":null,"raw_wpdb_replayed_outside_transaction":false}' . "\n";
	exit( HarnessContract::WORKER_EXIT_PROTOCOL_FAILURE );
}
