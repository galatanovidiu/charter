<?php
/**
 * Disposable Slice 0 CIMD freshness policy.
 *
 * @package GalatanOvidiu\Charter
 */

declare(strict_types=1);

namespace GalatanOvidiu\Charter\Tests\Prototype\CimdOutboundSafety;

use DateTimeImmutable;
use DateTimeZone;

/**
 * Calculates the accepted bounded RFC 9111 freshness state.
 *
 * @since 0.1.0
 */
final class FreshnessPolicy {

	private const FALLBACK_SECONDS  = 300;
	private const MAX_FRESH_SECONDS = 3600;

	/**
	 * Evaluates one successfully validated response.
	 *
	 * @since 0.1.0
	 *
	 * @param array<string, list<string>> $headers      Duplicate-preserving response headers.
	 * @param int                         $requestTime  Request wall-clock second.
	 * @param int                         $responseTime Response wall-clock second.
	 * @param int                         $now          Current wall-clock second.
	 * @return array{classification:string, fresh_until:int, current_age:int, reusable:bool, store:bool} Freshness state.
	 */
	public static function evaluate( array $headers, int $requestTime, int $responseTime, int $now ): array {
		$cacheControl = self::cacheControl( $headers['cache-control'] ?? array() );
		$currentAge   = self::currentAge( $headers, $requestTime, $responseTime, $now );
		$boundedAge   = $currentAge ?? 0;

		if ( $cacheControl['no_store'] ) {
			return self::result( 'no_store', $responseTime, $boundedAge, false, false );
		}

		if ( $cacheControl['no_cache'] ) {
			return self::result( 'no_cache', $responseTime, $boundedAge, false, true );
		}

		$lifetime = null;
		$usable   = $cacheControl['usable'] && null !== $currentAge;

		if ( $usable && null !== $cacheControl['max_age'] ) {
			$lifetime = $cacheControl['max_age'];
		} elseif ( $usable && array_key_exists( 'expires', $headers ) ) {
			$lifetime = self::expiresLifetime( $headers );
			$usable   = null !== $lifetime;
		}

		if ( ! $usable || null === $lifetime ) {
			$freshUntil = $responseTime + self::FALLBACK_SECONDS;
			return self::result( 'fallback', $freshUntil, $boundedAge, $now < $freshUntil, true );
		}

		$initialAge = max( 0, $boundedAge - max( 0, $now - $responseTime ) );
		$remaining  = max( 0, min( self::MAX_FRESH_SECONDS, $lifetime - $initialAge ) );
		$freshUntil = $responseTime + $remaining;
		$reusable   = $now < $freshUntil;

		return self::result( $reusable ? 'fresh' : 'stale', $freshUntil, $boundedAge, $reusable, true );
	}

	/**
	 * Parses the restrictive and max-age Cache-Control members.
	 *
	 * @param string[] $values Field values.
	 * @phpstan-param list<string> $values
	 * @return array{usable:bool, no_cache:bool, no_store:bool, max_age:?int} Parsed controls.
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
					continue;
				}
				if ( 'no-store' === strtolower( $member ) ) {
					$noStore = true;
					continue;
				}
				if ( 1 === preg_match( '/^max-age=(.*)$/iD', $member, $matches ) ) {
					$raw       = $matches[1];
					$maxAges[] = self::deltaSeconds( $raw );
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
	 * Parses a bounded delta-seconds value, including a quoted value.
	 *
	 * @param string $value Raw directive value.
	 * @return int|null Parsed value.
	 */
	private static function deltaSeconds( string $value ): ?int {
		if ( strlen( $value ) >= 2 && '"' === $value[0] && '"' === $value[ strlen( $value ) - 1 ] ) {
			$value = substr( $value, 1, -1 );
		}

		if ( 1 !== preg_match( '/^[0-9]+$/D', $value ) || strlen( $value ) > 18 ) {
			return null;
		}

		$parsed = filter_var( $value, FILTER_VALIDATE_INT, array( 'options' => array( 'min_range' => 0 ) ) );
		return is_int( $parsed ) ? $parsed : null;
	}

	/**
	 * Calculates complete current age or rejects malformed age metadata.
	 *
	 * @param array<string, list<string>> $headers      Response headers.
	 * @param int                         $requestTime  Request time.
	 * @param int                         $responseTime Response time.
	 * @param int                         $now          Current time.
	 * @return int|null Current age.
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

		$apparentAge         = max( 0, $responseTime - $date );
		$responseDelay       = max( 0, $responseTime - $requestTime );
		$correctedInitialAge = max( $apparentAge, $age + $responseDelay );
		$residentTime        = max( 0, $now - $responseTime );

		return $correctedInitialAge + $residentTime;
	}

	/**
	 * Calculates a valid Expires lifetime relative to Date.
	 *
	 * @param array<string, list<string>> $headers Response headers.
	 * @return int|null Freshness lifetime.
	 */
	private static function expiresLifetime( array $headers ): ?int {
		if (
			! array_key_exists( 'date', $headers )
			|| 1 !== count( $headers['date'] )
			|| 1 !== count( $headers['expires'] )
		) {
			return null;
		}

		$date    = self::httpDate( $headers['date'][0] );
		$expires = self::httpDate( $headers['expires'][0] );
		if ( null === $date || null === $expires ) {
			return null;
		}

		return max( 0, $expires - $date );
	}

	/**
	 * Parses one exact IMF-fixdate.
	 *
	 * @param string $value Field value.
	 * @return int|null Timestamp.
	 */
	private static function httpDate( string $value ): ?int {
		$zone = new DateTimeZone( 'GMT' );
		$date = DateTimeImmutable::createFromFormat( '!D, d M Y H:i:s \G\M\T', $value, $zone );
		if ( false === $date || $date->format( 'D, d M Y H:i:s \G\M\T' ) !== $value ) {
			return null;
		}

		return $date->getTimestamp();
	}

	/**
	 * Builds the fixed freshness result.
	 *
	 * @param string $classification Stable classification.
	 * @param int    $freshUntil     Exclusive freshness boundary.
	 * @param int    $currentAge     Complete current age.
	 * @param bool   $reusable       Whether the snapshot is reusable now.
	 * @param bool   $store          Whether diagnostic state may remain.
	 * @return array{classification:string, fresh_until:int, current_age:int, reusable:bool, store:bool} Result.
	 */
	private static function result(
		string $classification,
		int $freshUntil,
		int $currentAge,
		bool $reusable,
		bool $store
	): array {
		return array(
			'classification' => $classification,
			'fresh_until'    => $freshUntil,
			'current_age'    => $currentAge,
			'reusable'       => $reusable,
			'store'          => $store,
		);
	}
}
