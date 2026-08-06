<?php
/**
 * Bounded RFC 9111 freshness for validated CIMD responses.
 *
 * @package GalatanOvidiu\Charter
 */

declare(strict_types=1);

namespace GalatanOvidiu\Charter\OAuth;

use DateTimeImmutable;
use DateTimeZone;

/** Applies no-store/no-cache, response age, one-hour cap, and five-minute fallback. */
final class ClientMetadataFreshness {

	/**
	 * Evaluates one complete response against the accepted freshness policy.
	 *
	 * @param array<string,list<string>> $headers Duplicate-preserving response headers.
	 * @param int                        $requestTime Request wall time.
	 * @param int                        $responseTime Response wall time.
	 * @param int                        $now Evaluation wall time.
	 */
	public static function evaluate( array $headers, int $requestTime, int $responseTime, int $now ): ClientMetadataCachePolicy {
		$control = self::cacheControl( $headers['cache-control'] ?? array() );
		if ( $control['no_store'] || $control['no_cache'] ) {
			return new ClientMetadataCachePolicy( $responseTime, false );
		}

		$currentAge = self::currentAge( $headers, $requestTime, $responseTime, $now );
		$lifetime   = null;
		$usable     = $control['usable'] && null !== $currentAge;
		if ( $usable && null !== $control['max_age'] ) {
			$lifetime = $control['max_age'];
		} elseif ( $usable && array_key_exists( 'expires', $headers ) ) {
			$lifetime = self::expiresLifetime( $headers );
			$usable   = null !== $lifetime;
		}

		if ( ! $usable || null === $lifetime ) {
			$freshUntil = $responseTime + 300;
			return new ClientMetadataCachePolicy( $freshUntil, $now < $freshUntil );
		}

		$initialAge = max( 0, $currentAge - max( 0, $now - $responseTime ) );
		$remaining  = max( 0, min( 3600, $lifetime - $initialAge ) );
		$freshUntil = $responseTime + $remaining;

		return new ClientMetadataCachePolicy( $freshUntil, $now < $freshUntil );
	}

	/**
	 * Parses duplicate-preserving Cache-Control values.
	 *
	 * @param array $values Cache-Control field values.
	 * @phpstan-param list<string> $values
	 * @return array{usable:bool,no_cache:bool,no_store:bool,max_age:?int}
	 */
	private static function cacheControl( array $values ): array {
		$noCache = false;
		$noStore = false;
		$maxAges = array();
		foreach ( $values as $value ) {
			foreach ( explode( ',', $value ) as $member ) {
				$member = trim( $member );
				if ( 'no-cache' === strtolower( $member ) ) {
					$noCache = true;
				} elseif ( 'no-store' === strtolower( $member ) ) {
					$noStore = true;
				} elseif ( 1 === preg_match( '/^max-age=(.*)$/iD', $member, $matches ) ) {
					$maxAges[] = self::deltaSeconds( $matches[1] );
				}
			}
		}
		$usable = count( $maxAges ) <= 1 && ! in_array( null, $maxAges, true );

		return array(
			'usable'   => $usable,
			'no_cache' => $noCache,
			'no_store' => $noStore,
			'max_age'  => 1 === count( $maxAges ) && $usable ? $maxAges[0] : null,
		);
	}

	/**
	 * Parses one non-negative delta-seconds value.
	 *
	 * @param string $value Candidate delta-seconds value.
	 */
	private static function deltaSeconds( string $value ): ?int {
		if ( 2 <= strlen( $value ) && '"' === $value[0] && '"' === $value[ strlen( $value ) - 1 ] ) {
			$value = substr( $value, 1, -1 );
		}
		if ( 1 !== preg_match( '/^[0-9]+$/D', $value ) || 18 < strlen( $value ) ) {
			return null;
		}

		$parsed = filter_var( $value, FILTER_VALIDATE_INT, array( 'options' => array( 'min_range' => 0 ) ) );
		return is_int( $parsed ) ? $parsed : null;
	}

	/**
	 * Computes RFC 9111 current age.
	 *
	 * @param array<string,list<string>> $headers Duplicate-preserving response headers.
	 * @param int                        $requestTime Request wall time.
	 * @param int                        $responseTime Response wall time.
	 * @param int                        $now Evaluation wall time.
	 */
	private static function currentAge( array $headers, int $requestTime, int $responseTime, int $now ): ?int {
		$date = $responseTime;
		if ( array_key_exists( 'date', $headers ) ) {
			if ( 1 !== count( $headers['date'] ) ) {
				return null;
			}
			$date = self::httpDate( $headers['date'][0] );
			if ( null === $date ) {
				return null;
			}
		}
		$age = 0;
		if ( array_key_exists( 'age', $headers ) ) {
			if ( 1 !== count( $headers['age'] ) ) {
				return null;
			}
			$age = self::deltaSeconds( $headers['age'][0] );
			if ( null === $age ) {
				return null;
			}
		}

		$apparentAge   = max( 0, $responseTime - $date );
		$responseDelay = max( 0, $responseTime - $requestTime );
		return max( $apparentAge, $age + $responseDelay ) + max( 0, $now - $responseTime );
	}

	/**
	 * Computes an Expires freshness lifetime.
	 *
	 * @param array<string,list<string>> $headers Duplicate-preserving response headers.
	 */
	private static function expiresLifetime( array $headers ): ?int {
		if ( ! isset( $headers['date'], $headers['expires'] ) || 1 !== count( $headers['date'] ) || 1 !== count( $headers['expires'] ) ) {
			return null;
		}
		$date    = self::httpDate( $headers['date'][0] );
		$expires = self::httpDate( $headers['expires'][0] );
		return null === $date || null === $expires ? null : max( 0, $expires - $date );
	}

	/**
	 * Parses one exact IMF-fixdate value.
	 *
	 * @param string $value Candidate HTTP date.
	 */
	private static function httpDate( string $value ): ?int {
		$date = DateTimeImmutable::createFromFormat( '!D, d M Y H:i:s \G\M\T', $value, new DateTimeZone( 'GMT' ) );
		return false !== $date && $date->format( 'D, d M Y H:i:s \G\M\T' ) === $value ? $date->getTimestamp() : null;
	}

	/** Prevents direct construction. */
	private function __construct() {
	}
}
