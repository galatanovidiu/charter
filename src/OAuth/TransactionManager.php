<?php
/**
 * Owned database transaction boundary for OAuth lifecycle transitions.
 *
 * @package GalatanOvidiu\Charter
 */

declare(strict_types=1);

namespace GalatanOvidiu\Charter\OAuth;

use mysqli;
use mysqli_driver;
use mysqli_sql_exception;
use RuntimeException;
use Throwable;

/**
 * Runs one lifecycle transition on an independent fail-closed connection.
 *
 * @since 0.1.0
 */
final class TransactionManager {

	private const MAX_ATTEMPTS = 3;

	/**
	 * Runs and commits one complete transition.
	 *
	 * Only deadlocks and lock timeouts are retried from a new connection and a
	 * clean callback boundary. A lost connection or uncertain commit is never
	 * replayed by this class.
	 *
	 * @since 0.1.0
	 *
	 * @template T
	 * @param callable(mysqli): T $transition Transition callback.
	 * @return T Committed transition result.
	 * @throws RuntimeException When storage is unavailable or commit is uncertain.
	 * @throws Throwable When the transition callback fails.
	 */
	public function run( callable $transition ): mixed {
		$driver              = new mysqli_driver();
		$previous            = $driver->report_mode;
		$driver->report_mode = MYSQLI_REPORT_ERROR | MYSQLI_REPORT_STRICT;

		try {
			for ( $attempt = 1; $attempt <= self::MAX_ATTEMPTS; ++$attempt ) {
				$database = $this->connect();
				$phase    = 'begin';

				try {
					$database->begin_transaction();
					$phase  = 'transition';
					$result = $transition( $database );
					$phase  = 'commit';
					$database->commit();

					return $result;
				} catch ( mysqli_sql_exception $exception ) {
					$this->rollback( $database );
					if ( 'commit' !== $phase && $attempt < self::MAX_ATTEMPTS && self::isRetryable( $exception ) ) {
						usleep( 10000 * $attempt ); // phpcs:ignore WordPressVIPMinimum.Functions.RestrictedFunctions.usleep_usleep -- Bounded local deadlock backoff before a whole-transaction retry.
						continue;
					}

					if ( 'commit' === $phase ) {
						throw new RuntimeException( 'charter_database_commit_uncertain', 0, $exception ); // phpcs:ignore WordPress.Security.EscapeOutput.ExceptionNotEscaped -- Previous exception chaining is not response output.
					}

					throw new RuntimeException( 'charter_database_transaction_failed', 0, $exception ); // phpcs:ignore WordPress.Security.EscapeOutput.ExceptionNotEscaped -- Previous exception chaining is not response output.
				} catch ( Throwable $exception ) {
					$this->rollback( $database );
					throw $exception;
				} finally {
					if ( $database->thread_id > 0 ) {
						$database->close();
					}
				}
			}
		} finally {
			$driver->report_mode = $previous;
		}

		throw new RuntimeException( 'charter_database_transaction_failed' );
	}

	/**
	 * Opens one connection that no WordPress query can transparently reconnect.
	 *
	 * @since 0.1.0
	 *
	 * @throws RuntimeException When connection configuration or establishment fails.
	 */
	private function connect(): mysqli {
		if (
			! defined( 'DB_HOST' )
			|| ! defined( 'DB_USER' )
			|| ! defined( 'DB_PASSWORD' )
			|| ! defined( 'DB_NAME' )
		) {
			throw new RuntimeException( 'charter_database_configuration_unavailable' );
		}

		$hostValue = constant( 'DB_HOST' );
		$user      = constant( 'DB_USER' );
		$password  = constant( 'DB_PASSWORD' );
		$name      = constant( 'DB_NAME' );
		if ( ! is_string( $hostValue ) || ! is_string( $user ) || ! is_string( $password ) || ! is_string( $name ) ) {
			throw new RuntimeException( 'charter_database_configuration_invalid' );
		}

		$address = self::parseHost( $hostValue );

		try {
			$database = new mysqli();
			$database->real_connect(
				$address['host'],
				$user,
				$password,
				$name,
				$address['port'],
				$address['socket']
			);
			$charset = self::charset();
			if ( '' !== $charset ) {
				$database->set_charset( $charset );
			}
		} catch ( mysqli_sql_exception $exception ) {
			throw new RuntimeException( 'charter_database_connection_failed', 0, $exception ); // phpcs:ignore WordPress.Security.EscapeOutput.ExceptionNotEscaped -- Previous exception chaining is not response output.
		}

		return $database;
	}

	/**
	 * Parses the WordPress DB_HOST forms needed by mysqli_real_connect().
	 *
	 * @since 0.1.0
	 *
	 * @param string $value WordPress database host value.
	 * @return array{host: string, port: int, socket: string|null}
	 * @throws RuntimeException When the host value is invalid.
	 */
	private static function parseHost( string $value ): array {
		$host   = $value;
		$port   = 3306;
		$socket = null;

		if ( 1 === preg_match( '/^\[([^]]+)\](?::([0-9]+))?(?::(.+))?$/D', $value, $matches ) ) {
			$host = $matches[1];
			if ( isset( $matches[2] ) && '' !== $matches[2] ) {
				$port = (int) $matches[2];
			}
			if ( isset( $matches[3] ) ) {
				$socket = $matches[3];
			}
		} elseif ( 1 === preg_match( '/^([^:]+):([0-9]+)(?::(.+))?$/D', $value, $matches ) ) {
			$host = $matches[1];
			$port = (int) $matches[2];
			if ( isset( $matches[3] ) ) {
				$socket = $matches[3];
			}
		} elseif ( 1 === preg_match( '/^([^:]+):(.+)$/D', $value, $matches ) && str_starts_with( $matches[2], '/' ) ) {
			$host   = $matches[1];
			$socket = $matches[2];
		}

		if ( '' === $host || $port < 1 || $port > 65535 ) {
			throw new RuntimeException( 'charter_database_host_invalid' );
		}

		return array(
			'host'   => $host,
			'port'   => $port,
			'socket' => $socket,
		);
	}

	/**
	 * Returns WordPress's configured connection charset.
	 *
	 * @since 0.1.0
	 */
	private static function charset(): string {
		global $wpdb;

		if ( $wpdb instanceof \wpdb ) {
			return $wpdb->charset;
		}

		$charset = defined( 'DB_CHARSET' ) ? constant( 'DB_CHARSET' ) : '';

		return is_string( $charset ) ? $charset : '';
	}

	/**
	 * Rolls back without hiding the transition's original failure.
	 *
	 * @since 0.1.0
	 *
	 * @param mysqli $database Owned connection.
	 */
	private function rollback( mysqli $database ): void {
		try {
			$database->rollback();
		} catch ( mysqli_sql_exception ) {
			return;
		}
	}

	/**
	 * Recognizes transaction failures that are safe to replay from the start.
	 *
	 * @since 0.1.0
	 *
	 * @param mysqli_sql_exception $exception Database failure.
	 */
	private static function isRetryable( mysqli_sql_exception $exception ): bool {
		return in_array( $exception->getCode(), array( 1205, 1213 ), true );
	}
}
