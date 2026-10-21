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
		$bucket      = self::bucketDigest( $issuer, $surface, $subject );
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
	 * Consumes a failure-sensitive counter with bounded exponential backoff.
	 *
	 * Callers consume before expensive credential work and clear the exact bucket
	 * only after the complete operation succeeds.
	 *
	 * @param string $issuer Exact issuer.
	 * @param string $surface Stable endpoint surface.
	 * @param string $subject Non-secret bucket subject.
	 * @param int    $limit Allowed attempts before backoff.
	 * @param int    $windowSeconds Initial failure window.
	 * @param int    $maximumBackoff Maximum backoff in seconds.
	 * @param int    $timestamp Current timestamp.
	 * @throws RuntimeException When policy or persistence is invalid.
	 */
	public function consumeWithBackoff( string $issuer, string $surface, string $subject, int $limit, int $windowSeconds, int $maximumBackoff, int $timestamp ): RateLimitDecision {
		if ( '' === $issuer || 1 !== preg_match( '/^[a-z0-9_]{1,64}$/D', $surface ) || '' === $subject || 1 > $limit || 1 > $windowSeconds || $maximumBackoff < $windowSeconds ) {
			throw new RuntimeException( 'charter_rate_limit_policy_invalid' );
		}
		$bucket = self::bucketDigest( $issuer, $surface, $subject );

		return $this->transactions->run(
			static function ( mysqli $database ) use ( $bucket, $limit, $windowSeconds, $maximumBackoff, $timestamp ): RateLimitDecision {
				$table  = self::quotedTable( Schema::rateLimitTable() );
				$result = $database->execute_query(
					"SELECT window_started_at,window_seconds,request_count,expires_at FROM {$table} WHERE bucket_digest = ? LIMIT 1 FOR UPDATE",
					array( $bucket )
				); // phpcs:ignore WordPress.DB.RestrictedFunctions.mysql_mysqli -- Failure counter mutation uses one owned transaction.
				if ( ! $result instanceof mysqli_result ) {
					throw new RuntimeException( 'charter_rate_limit_query_failed' );
				}
				$row = $result->fetch_assoc();
				$result->free();

				$storedCount  = is_array( $row ) ? self::integerValue( $row['request_count'] ?? null ) : null;
				$storedExpiry = is_array( $row ) ? self::integerValue( $row['expires_at'] ?? null ) : null;
				if ( null === $storedCount || null === $storedExpiry || $storedExpiry <= $timestamp ) {
					$count     = 1;
					$backoff   = $windowSeconds;
					$expiresAt = $timestamp + $windowSeconds;
				} else {
					$count = $storedCount + 1;
					$level = 0;
					if ( $count > $limit ) {
						$level = intdiv( $count - $limit - 1, $limit );
					}
					$multiplier = 2 ** min( 10, $level );
					$backoff    = min( $maximumBackoff, $windowSeconds * $multiplier );
					$expiresAt  = max( $storedExpiry, $timestamp + $backoff );
				}

				$result = $database->execute_query(
					"INSERT INTO {$table} (bucket_digest,window_started_at,window_seconds,request_count,expires_at)
					VALUES (?,?,?,?,?) ON DUPLICATE KEY UPDATE window_started_at = VALUES(window_started_at), window_seconds = VALUES(window_seconds), request_count = VALUES(request_count), expires_at = VALUES(expires_at)",
					array( $bucket, $timestamp, $backoff, $count, $expiresAt )
				); // phpcs:ignore WordPress.DB.RestrictedFunctions.mysql_mysqli -- Exact failure bucket replacement remains inside the locked owned transaction.
				if ( true !== $result ) {
					throw new RuntimeException( 'charter_rate_limit_update_failed' );
				}

				return new RateLimitDecision( $count <= $limit, $count, $limit, max( 1, $expiresAt - $timestamp ) );
			}
		);
	}

	/**
	 * Clears one exact failure-specific bucket after complete success.
	 *
	 * @param string $issuer Exact issuer.
	 * @param string $surface Stable endpoint surface.
	 * @param string $subject Non-secret bucket subject.
	 * @throws RuntimeException When persistence fails.
	 */
	public function clear( string $issuer, string $surface, string $subject ): void {
		if ( '' === $issuer || 1 !== preg_match( '/^[a-z0-9_]{1,64}$/D', $surface ) || '' === $subject ) {
			throw new RuntimeException( 'charter_rate_limit_policy_invalid' );
		}
		$bucket = self::bucketDigest( $issuer, $surface, $subject );
		$this->transactions->run(
			static function ( mysqli $database ) use ( $bucket ): void {
				$table = self::quotedTable( Schema::rateLimitTable() );
				if ( true !== $database->execute_query( "DELETE FROM {$table} WHERE bucket_digest = ?", array( $bucket ) ) ) { // phpcs:ignore WordPress.DB.RestrictedFunctions.mysql_mysqli -- Exact failure-bucket relief uses an owned transaction.
					throw new RuntimeException( 'charter_rate_limit_cleanup_failed' );
				}
			}
		);
	}

	/**
	 * Relieves only the caller's successful reservation from one shared bucket.
	 *
	 * Earlier failures remain effective, so an unrelated success cannot erase an
	 * attacker's source-wide backoff.
	 *
	 * @param string $issuer Exact issuer.
	 * @param string $surface Stable endpoint surface.
	 * @param string $subject Non-secret bucket subject.
	 * @throws RuntimeException When persistence fails.
	 */
	public function relieve( string $issuer, string $surface, string $subject ): void {
		if ( '' === $issuer || 1 !== preg_match( '/^[a-z0-9_]{1,64}$/D', $surface ) || '' === $subject ) {
			throw new RuntimeException( 'charter_rate_limit_policy_invalid' );
		}
		$bucket = self::bucketDigest( $issuer, $surface, $subject );
		$this->transactions->run(
			static function ( mysqli $database ) use ( $bucket ): void {
				$table  = self::quotedTable( Schema::rateLimitTable() );
				$result = $database->execute_query( "SELECT request_count FROM {$table} WHERE bucket_digest = ? LIMIT 1 FOR UPDATE", array( $bucket ) ); // phpcs:ignore WordPress.DB.RestrictedFunctions.mysql_mysqli -- Exact success relief remains inside the locked owned transaction.
				if ( ! $result instanceof mysqli_result ) {
					throw new RuntimeException( 'charter_rate_limit_query_failed' );
				}
				$row = $result->fetch_assoc();
				$result->free();
				$count = is_array( $row ) ? self::integerValue( $row['request_count'] ?? null ) : null;
				if ( null === $count ) {
					return;
				}

				$updated = 1 >= $count
					? $database->execute_query( "DELETE FROM {$table} WHERE bucket_digest = ?", array( $bucket ) )
					: $database->execute_query( "UPDATE {$table} SET request_count = request_count - 1 WHERE bucket_digest = ?", array( $bucket ) );
				if ( true !== $updated ) {
					throw new RuntimeException( 'charter_rate_limit_cleanup_failed' );
				}
			}
		);
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

	/**
	 * Returns the non-secret exact bucket digest.
	 *
	 * @param string $issuer Exact issuer.
	 * @param string $surface Stable endpoint surface.
	 * @param string $subject Non-secret bucket subject.
	 */
	private static function bucketDigest( string $issuer, string $surface, string $subject ): string {
		return hash( 'sha256', $issuer . "\0" . $surface . "\0" . $subject );
	}

	/**
	 * Converts one non-negative stored integer.
	 *
	 * @param mixed $value Stored value.
	 */
	private static function integerValue( mixed $value ): ?int {
		return is_int( $value ) && 0 <= $value ? $value : ( is_string( $value ) && ctype_digit( $value ) ? (int) $value : null );
	}
}
