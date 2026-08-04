<?php
/**
 * Actual WordPress wpdb reconnect red probe for Slice 0 P1.
 *
 * @package GalatanOvidiu\Charter
 */

declare(strict_types=1);

namespace GalatanOvidiu\Charter\Tests\Fixtures\AtomicLifecycle;

// phpcs:disable Squiz.Commenting, WordPress.DB.PreparedSQL.NotPrepared -- Fixed disposable table names and actual wpdb behavior are the red proof boundary.

use Closure;
use GalatanOvidiu\Charter\Tests\Prototype\AtomicLifecycle\AtomicLifecycleCheckpoints;
use GalatanOvidiu\Charter\Tests\Prototype\AtomicLifecycle\AtomicLifecycleSchema;
use RuntimeException;

/**
 * Demonstrates that raw wpdb can replay one statement after losing a transaction.
 */
final class RawWpdbReconnectProbe {

	/**
	 * Runs the expected red behavior without returning SQL or connection material.
	 *
	 * @param LaneConfiguration          $lane       Current disposable lane.
	 * @param Closure(string, int): void $checkpoint Checkpoint observer.
	 * @return array{replayed_outside_transaction: bool, connection_changed: bool, connection_id: int}
	 */
	public static function run( LaneConfiguration $lane, Closure $checkpoint ): array {
		$wordpressDirectory = rtrim( $lane->wordpressSourceDirectory(), '/' );
		$loadFile           = $wordpressDirectory . '/wp-includes/load.php';
		$pluginFile         = $wordpressDirectory . '/wp-includes/plugin.php';
		$wpdbFile           = $wordpressDirectory . '/wp-includes/class-wpdb.php';

		if ( ! is_file( $loadFile ) || ! is_file( $pluginFile ) || ! is_file( $wpdbFile ) ) {
			throw new RuntimeException( 'Exact WordPress wpdb source is unavailable.' );
		}

		self::defineWordPressConstants( $lane->wordpressSourceDirectory() );
		require_once $loadFile;
		require_once $pluginFile;
		require_once $wpdbFile;

		$host     = self::requiredEnvironment( 'CHARTER_ATOMIC_DB_HOST' );
		$port     = self::requiredEnvironment( 'CHARTER_ATOMIC_DB_PORT' );
		$user     = self::requiredEnvironment( 'CHARTER_ATOMIC_DB_USER' );
		$password = self::requiredEnvironment( 'CHARTER_ATOMIC_DB_PASSWORD' );
		$name     = self::requiredEnvironment( 'CHARTER_ATOMIC_DB_NAME' );
		$dbHost   = $host . ':' . $port;
		$wpdb     = new class( $user, $password, $name, $dbHost ) extends \wpdb {

			/**
			 * Returns the current physical connection identity.
			 */
			public function proofConnectionId(): int {
				if ( ! $this->dbh instanceof \mysqli ) {
					return 0;
				}

				return (int) $this->dbh->thread_id;
			}
		};
		$previous = $wpdb->suppress_errors( true );
		$wpdb->hide_errors();

		try {
			$isolationSet      = $wpdb->query(
				'SET SESSION TRANSACTION ISOLATION LEVEL ' . $lane->isolation()
			);
			$isolationVariable = 'mysql' === $lane->databaseFamily()
				? '@@transaction_isolation'
				: '@@tx_isolation';
			$observedIsolation = $wpdb->get_var( 'SELECT ' . $isolationVariable );

			if (
				false === $isolationSet
				|| ! is_string( $observedIsolation )
				|| $lane->isolation() !== strtoupper( str_replace( '-', ' ', $observedIsolation ) )
			) {
				throw new RuntimeException( 'Raw wpdb isolation precondition failed.' );
			}

			$started = $wpdb->query( 'START TRANSACTION' );
			$first   = $wpdb->query(
				'UPDATE ' . AtomicLifecycleSchema::SENTINELS . ' SET value_number = value_number + 1 WHERE sentinel_id = 1'
			);
			$before  = $wpdb->proofConnectionId();

			if ( false === $started || false === $first || 1 > $before ) {
				throw new RuntimeException( 'Raw wpdb red precondition failed.' );
			}

			$checkpoint( AtomicLifecycleCheckpoints::AFTER_CONNECTION_MUTATION, $before );

			$second = $wpdb->query(
				'UPDATE ' . AtomicLifecycleSchema::SENTINELS . ' SET value_number = value_number + 1 WHERE sentinel_id = 2'
			);
			$after  = $wpdb->proofConnectionId();

			return array(
				'replayed_outside_transaction' => false !== $second && $after !== $before,
				'connection_changed'           => $after !== $before,
				'connection_id'                => 0 < $after ? $after : $before,
			);
		} finally {
			$wpdb->suppress_errors( $previous );
		}
	}

	private static function defineWordPressConstants( string $wordpressDirectory ): void {
		if ( ! defined( 'ABSPATH' ) ) {
			// phpcs:ignore WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedConstantFound -- Required by the real WordPress wpdb class.
			define( 'ABSPATH', rtrim( $wordpressDirectory, '/' ) . '/' );
		}

		if ( ! defined( 'WP_DEBUG' ) ) {
			define( 'WP_DEBUG', false );
		}

		if ( ! defined( 'WP_DEBUG_DISPLAY' ) ) {
			define( 'WP_DEBUG_DISPLAY', false );
		}

		if ( ! defined( 'WP_DEBUG_LOG' ) ) {
			define( 'WP_DEBUG_LOG', false );
		}
	}

	private static function requiredEnvironment( string $name ): string {
		$value = getenv( $name );

		if ( false === $value || '' === $value ) {
			throw new RuntimeException( 'Private raw wpdb probe configuration is unavailable.' );
		}

		return $value;
	}
}
