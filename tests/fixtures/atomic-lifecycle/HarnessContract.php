<?php
/**
 * Fixed public contract for the disposable Slice 0 P1 harness.
 *
 * @package GalatanOvidiu\Charter
 */

declare(strict_types=1);

namespace GalatanOvidiu\Charter\Tests\Fixtures\AtomicLifecycle;

// phpcs:disable Squiz.Commenting.FunctionCommentThrowTag.Missing -- Invalid bounded overrides intentionally collapse to the fixed runner failure boundary.

/**
 * Defines the bounded matrix, scenarios, protocol, and output vocabulary.
 */
final class HarnessContract {

	public const WORDPRESS_VERSION = '6.9.5';

	public const WORDPRESS_RUNTIME_IMAGE = 'wordpress:cli-php8.4';

	public const DEFAULT_WORKERS = 8;

	public const MINIMUM_DECISIVE_WORKERS = 8;

	public const MAXIMUM_WORKERS = 32;

	public const DEFAULT_ROUNDS = 50;

	public const MINIMUM_DECISIVE_ROUNDS = 50;

	public const MAXIMUM_ROUNDS = 500;

	public const DEFAULT_WORKER_TIMEOUT_SECONDS = 30;

	public const MAXIMUM_WORKER_TIMEOUT_SECONDS = 120;

	public const DEFAULT_LANE_TIMEOUT_SECONDS = 3600;

	public const MAXIMUM_LANE_TIMEOUT_SECONDS = 7200;

	public const DEFAULT_LOCK_WAIT_TIMEOUT_SECONDS = 2;

	public const PROTOCOL_VERSION = 1;

	public const MESSAGE_READY = 'ready';

	public const MESSAGE_CHECKPOINT = 'checkpoint';

	public const MESSAGE_RESULT = 'result';

	public const COMMAND_RUN = 'run';

	public const COMMAND_RELEASE = 'release';

	public const COMMAND_STOP = 'stop';

	public const CASE_PREFLIGHT = 'preflight';

	public const CASE_CODE_EXCHANGE = 'code_exchange';

	public const CASE_CODE_RACE = 'code_race';

	public const CASE_CODE_REPLAY = 'code_replay';

	public const CASE_CODE_WORKER_DEATH = 'code_worker_death';

	public const CASE_CODE_COMMIT_AMBIGUITY = 'code_commit_ambiguity';

	public const CASE_REFRESH_ROTATION = 'refresh_rotation';

	public const CASE_REFRESH_RACE = 'refresh_race';

	public const CASE_REFRESH_ANCESTOR_REPLAY = 'refresh_ancestor_replay';

	public const CASE_DEADLOCK = 'deadlock_recovery';

	public const CASE_LOCK_TIMEOUT = 'lock_timeout_recovery';

	public const CASE_CONNECTION_LOSS = 'connection_loss_boundary';

	public const CASE_CLEANUP = 'cleanup';

	public const ACTION_EXCHANGE_CODE = 'exchange_code';

	public const ACTION_SEED_CODE = 'seed_code';

	public const ACTION_SEED_REFRESH = 'seed_refresh';

	public const ACTION_EXCHANGE_UNKNOWN_CODE = 'exchange_unknown_code';

	public const ACTION_ROTATE_REFRESH = 'rotate_refresh';

	public const ACTION_SENTINEL = 'sentinel';

	public const ACTION_CONNECTION_LOSS = 'connection_loss';

	public const ACTION_RAW_WPDB_CONNECTION_LOSS = 'raw_wpdb_connection_loss';

	public const OUTCOME_WINNER = 'winner';

	public const OUTCOME_REPLAY = 'replay';

	public const OUTCOME_INVALID = 'invalid';

	public const OUTCOME_DEADLOCK = 'deadlock';

	public const OUTCOME_LOCK_TIMEOUT = 'lock_timeout';

	public const OUTCOME_ROLLED_BACK = 'rolled_back';

	public const OUTCOME_CONNECTION_LOST = 'connection_lost';

	public const OUTCOME_WORKER_DIED = 'worker_died';

	public const OUTCOME_COMMIT_AMBIGUOUS = 'commit_ambiguous';

	public const OUTCOME_PASSED = 'passed';

	public const OUTCOME_FAILED = 'failed';

	public const WORKER_EXIT_EXPECTED_DEATH = 70;

	public const WORKER_EXIT_PROTOCOL_FAILURE = 71;

	/**
	 * Exact database and isolation matrix required by the approved plan.
	 *
	 * @return list<array{family: string, version: string, image: string, isolation: string, isolation_sql: string, snapshot_isolation: bool|null}>
	 */
	public static function databaseMatrix(): array {
		$servers    = array(
			array(
				'family'             => 'mysql',
				'version'            => '8.0.46',
				'image'              => 'mysql:8.0.46',
				'snapshot_isolation' => null,
			),
			array(
				'family'             => 'mysql',
				'version'            => '8.4.11',
				'image'              => 'mysql:8.4.11',
				'snapshot_isolation' => null,
			),
			array(
				'family'             => 'mariadb',
				'version'            => '10.11.18',
				'image'              => 'mariadb:10.11.18',
				'snapshot_isolation' => false,
			),
			array(
				'family'             => 'mariadb',
				'version'            => '12.3.2',
				'image'              => 'mariadb:12.3.2',
				'snapshot_isolation' => true,
			),
		);
		$isolations = array(
			array(
				'isolation'     => 'REPEATABLE READ',
				'isolation_sql' => 'REPEATABLE READ',
			),
			array(
				'isolation'     => 'READ COMMITTED',
				'isolation_sql' => 'READ COMMITTED',
			),
		);
		$matrix     = array();

		foreach ( $servers as $server ) {
			foreach ( $isolations as $isolation ) {
				$matrix[] = $server + $isolation;
			}
		}

		return $matrix;
	}

	/**
	 * Ordered scenarios required in every lane.
	 *
	 * @return list<string>
	 */
	public static function cases(): array {
		return array(
			self::CASE_PREFLIGHT,
			self::CASE_CODE_EXCHANGE,
			self::CASE_CODE_RACE,
			self::CASE_CODE_REPLAY,
			self::CASE_CODE_WORKER_DEATH,
			self::CASE_CODE_COMMIT_AMBIGUITY,
			self::CASE_REFRESH_ROTATION,
			self::CASE_REFRESH_RACE,
			self::CASE_REFRESH_ANCESTOR_REPLAY,
			self::CASE_DEADLOCK,
			self::CASE_LOCK_TIMEOUT,
			self::CASE_CONNECTION_LOSS,
		);
	}

	/**
	 * Permitted worker outcomes.
	 *
	 * @return list<string>
	 */
	public static function outcomes(): array {
		return array(
			self::OUTCOME_WINNER,
			self::OUTCOME_REPLAY,
			self::OUTCOME_INVALID,
			self::OUTCOME_DEADLOCK,
			self::OUTCOME_LOCK_TIMEOUT,
			self::OUTCOME_ROLLED_BACK,
			self::OUTCOME_CONNECTION_LOST,
			self::OUTCOME_WORKER_DIED,
			self::OUTCOME_COMMIT_AMBIGUOUS,
			self::OUTCOME_PASSED,
			self::OUTCOME_FAILED,
		);
	}

	/**
	 * Reads a bounded integer override.
	 *
	 * @param string $name    Environment variable name.
	 * @param int    $fallback Default value.
	 * @param int    $minimum Minimum accepted value.
	 * @param int    $maximum Maximum accepted value.
	 */
	public static function boundedEnvironmentInteger(
		string $name,
		int $fallback,
		int $minimum,
		int $maximum
	): int {
		$value = getenv( $name );

		if ( false === $value || '' === $value ) {
			return $fallback;
		}

		if ( ! ctype_digit( $value ) ) {
			throw new \InvalidArgumentException( 'Invalid bounded harness override.' );
		}

		$integer = (int) $value;
		if ( $integer < $minimum || $integer > $maximum ) {
			throw new \InvalidArgumentException( 'Harness override is outside the approved bound.' );
		}

		return $integer;
	}
}
