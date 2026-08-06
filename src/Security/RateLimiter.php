<?php
/**
 * OAuth abuse-surface rate limits.
 *
 * @package GalatanOvidiu\Charter
 */

declare(strict_types=1);

namespace GalatanOvidiu\Charter\Security;

use GalatanOvidiu\Charter\OAuth\TransactionManager;
use GalatanOvidiu\Charter\Schema;
use mysqli;
use mysqli_result;
use RuntimeException;

/**
 * Applies atomic issuer-scoped fixed-window counters.
 *
 * @since 0.1.0
 */
final class RateLimiter {

	/**
	 * Owned non-reconnecting transaction service.
	 *
	 * @var TransactionManager
	 */
	private readonly TransactionManager $transactions;

	/**
	 * Creates the rate limiter.
	 *
	 * @param TransactionManager|null $transactions Owned transaction service.
	 */
	public function __construct( ?TransactionManager $transactions = null ) {
		$this->transactions = $transactions ?? new TransactionManager();
	}

	/**
	 * Consumes one counter position.
	 *
	 * @param string $issuer Exact issuer.
	 * @param string $surface Stable endpoint surface.
	 * @param string $subject Non-secret bucket subject.
	 * @param int    $limit Maximum requests per window.
	 * @param int    $windowSeconds Window size.
	 * @param int    $timestamp Current timestamp.
	 * @throws RuntimeException When policy or persistence is invalid.
	 */
	public function consume( string $issuer, string $surface, string $subject, int $limit, int $windowSeconds, int $timestamp ): RateLimitDecision {
		if ( '' === $issuer || 1 !== preg_match( '/^[a-z0-9_]{1,64}$/D', $surface ) || '' === $subject || 1 > $limit || 1 > $windowSeconds ) {
			throw new RuntimeException( 'charter_rate_limit_policy_invalid' );
		}

		$windowStart = $timestamp - ( $timestamp % $windowSeconds );
		$bucket      = hash( 'sha256', $issuer . "\0" . $surface . "\0" . $subject );
		$count       = $this->transactions->run(
			static function ( mysqli $database ) use ( $bucket, $windowStart, $windowSeconds ): int {
				$table  = self::quotedTable( Schema::rateLimitTable() );
				$result = $database->execute_query(
					"INSERT INTO {$table} (bucket_digest,window_started_at,window_seconds,request_count,expires_at)
					VALUES (?,?,?,?,?)
					ON DUPLICATE KEY UPDATE
					request_count = IF(window_started_at = VALUES(window_started_at) AND window_seconds = VALUES(window_seconds), request_count + 1, 1),
					window_started_at = VALUES(window_started_at), window_seconds = VALUES(window_seconds), expires_at = VALUES(expires_at)",
					array( $bucket, $windowStart, $windowSeconds, 1, $windowStart + $windowSeconds )
				); // phpcs:ignore WordPress.DB.RestrictedFunctions.mysql_mysqli -- Atomic abuse counter uses an owned non-reconnecting transaction.
				if ( true !== $result ) {
					throw new RuntimeException( 'charter_rate_limit_update_failed' );
				}

				$result = $database->execute_query( "SELECT request_count FROM {$table} WHERE bucket_digest = ? LIMIT 1", array( $bucket ) ); // phpcs:ignore WordPress.DB.RestrictedFunctions.mysql_mysqli -- Reads the exact atomic counter just updated.
				if ( ! $result instanceof mysqli_result ) {
					throw new RuntimeException( 'charter_rate_limit_query_failed' );
				}
				$row = $result->fetch_assoc();
				$result->free();
				$value = is_array( $row ) ? ( $row['request_count'] ?? null ) : null;
				if ( ! is_int( $value ) && ! ( is_string( $value ) && ctype_digit( $value ) ) ) {
					throw new RuntimeException( 'charter_rate_limit_query_failed' );
				}

				return (int) $value;
			}
		);

		return new RateLimitDecision( $count <= $limit, $count, $limit, max( 1, $windowStart + $windowSeconds - $timestamp ) );
	}

	/**
	 * Deletes current-site counters during tests or uninstall.
	 */
	public function deleteAll(): void {
		$this->transactions->run(
			static function ( mysqli $database ): void {
				$table = self::quotedTable( Schema::rateLimitTable() );
				if ( true !== $database->query( "DELETE FROM {$table}" ) ) { // phpcs:ignore WordPress.DB.RestrictedFunctions.mysql_mysqli -- Bounded owned cleanup.
					throw new RuntimeException( 'charter_rate_limit_cleanup_failed' );
				}
			}
		);
	}

	/**
	 * Quotes one trusted WordPress-derived table identifier.
	 *
	 * @param string $table Table identifier.
	 * @throws RuntimeException When the identifier is invalid.
	 */
	private static function quotedTable( string $table ): string {
		if ( 1 !== preg_match( '/^[A-Za-z0-9_]+$/D', $table ) ) {
			throw new RuntimeException( 'charter_database_table_invalid' );
		}

		return '`' . $table . '`';
	}
}
