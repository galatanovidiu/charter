<?php
/**
 * Slice 0 CIMD freshness-policy tests.
 *
 * @package GalatanOvidiu\Charter
 */

declare(strict_types=1);

namespace GalatanOvidiu\Charter\Tests\Integration\CimdOutboundSafety;

use GalatanOvidiu\Charter\Tests\Prototype\CimdOutboundSafety\FreshnessPolicy;
use PHPUnit\Framework\TestCase;

/**
 * Proves the exact bounded RFC 9111 freshness policy accepted for CIMD.
 *
 * @since 0.1.0
 */
final class FreshnessPolicyTest extends TestCase {

	/**
	 * Verifies the exact five-minute fallback without usable freshness metadata.
	 *
	 * @since 0.1.0
	 */
	public function testUsesExactlyFiveMinutesWithoutFreshnessMetadata(): void {
		self::assertSame(
			array(
				'classification' => 'fallback',
				'fresh_until'    => 1300,
				'current_age'    => 0,
				'reusable'       => true,
				'store'          => true,
			),
			FreshnessPolicy::evaluate( array(), 1000, 1000, 1000 )
		);
	}

	/**
	 * Verifies shorter max-age values, the exact cap, and values above the cap.
	 *
	 * @since 0.1.0
	 *
	 * @dataProvider maxAgeProvider
	 *
	 * @param string $maxAge             Cache-Control max-age value.
	 * @param int    $expectedFreshUntil Expected absolute boundary.
	 */
	public function testCapsValidMaxAgeAtOneHour( string $maxAge, int $expectedFreshUntil ): void {
		$result = FreshnessPolicy::evaluate(
			array( 'cache-control' => array( 'max-age=' . $maxAge ) ),
			1000,
			1000,
			1000
		);

		self::assertSame( 'fresh', $result['classification'] );
		self::assertSame( $expectedFreshUntil, $result['fresh_until'] );
		self::assertSame( 0, $result['current_age'] );
		self::assertTrue( $result['reusable'] );
		self::assertTrue( $result['store'] );
	}

	/**
	 * Verifies corrected Age, response delay, apparent age, and resident time.
	 *
	 * @since 0.1.0
	 */
	public function testSubtractsTheCompleteRfc9111CurrentAge(): void {
		$result = FreshnessPolicy::evaluate(
			array(
				'cache-control' => array( 'max-age=600' ),
				'date'          => array( self::httpDate( 900 ) ),
				'age'           => array( '120' ),
			),
			950,
			1000,
			1030
		);

		// max( apparent age 100, Age 120 ) + response delay 50 + resident time 30.
		self::assertSame( 200, $result['current_age'] );
		self::assertSame( 1430, $result['fresh_until'] );
		self::assertSame( 'fresh', $result['classification'] );
		self::assertTrue( $result['reusable'] );
	}

	/**
	 * Verifies apparent age wins when the Age field is lower or absent.
	 *
	 * @since 0.1.0
	 *
	 * @dataProvider lowerAgeProvider
	 *
	 * @param array<string, list<string>> $ageHeader Optional Age field.
	 */
	public function testUsesApparentAgeWhenItIsGreater( array $ageHeader ): void {
		$result = FreshnessPolicy::evaluate(
			array_merge(
				array(
					'cache-control' => array( 'max-age=300' ),
					'date'          => array( self::httpDate( 900 ) ),
				),
				$ageHeader
			),
			1000,
			1000,
			1000
		);

		self::assertSame( 100, $result['current_age'] );
		self::assertSame( 1200, $result['fresh_until'] );
		self::assertTrue( $result['reusable'] );
	}

	/**
	 * Verifies Expires/Date freshness when max-age is absent.
	 *
	 * @since 0.1.0
	 */
	public function testUsesValidExpiresAndDateWithCompleteAge(): void {
		$result = FreshnessPolicy::evaluate(
			array(
				'date'    => array( self::httpDate( 1000 ) ),
				'expires' => array( self::httpDate( 1600 ) ),
				'age'     => array( '100' ),
			),
			990,
			1000,
			1020
		);

		self::assertSame( 130, $result['current_age'] );
		self::assertSame( 1490, $result['fresh_until'] );
		self::assertSame( 'fresh', $result['classification'] );
		self::assertTrue( $result['reusable'] );
	}

	/**
	 * Verifies valid max-age takes precedence over Expires.
	 *
	 * @since 0.1.0
	 */
	public function testValidMaxAgeTakesPrecedenceOverExpires(): void {
		$result = FreshnessPolicy::evaluate(
			array(
				'cache-control' => array( 'max-age=60' ),
				'date'          => array( self::httpDate( 1000 ) ),
				'expires'       => array( self::httpDate( 4600 ) ),
			),
			1000,
			1000,
			1000
		);

		self::assertSame( 1060, $result['fresh_until'] );
		self::assertSame( 'fresh', $result['classification'] );
	}

	/**
	 * Verifies malformed, repeated, conflicting, or overflowed freshness falls back.
	 *
	 * @since 0.1.0
	 *
	 * @dataProvider unusableFreshnessProvider
	 *
	 * @param array<string, list<string>> $headers Unusable freshness metadata.
	 */
	public function testUsesFiveMinuteFallbackForUnusableFreshness( array $headers ): void {
		$result = FreshnessPolicy::evaluate( $headers, 1000, 1000, 1000 );

		self::assertSame( 'fallback', $result['classification'] );
		self::assertSame( 1300, $result['fresh_until'] );
		self::assertTrue( $result['reusable'] );
		self::assertTrue( $result['store'] );
	}

	/**
	 * Verifies no-cache and no-store are never reusable after authorization.
	 *
	 * @since 0.1.0
	 *
	 * @dataProvider restrictiveDirectiveProvider
	 *
	 * @param string $directive              Cache-Control directive.
	 * @param string $expectedClassification Expected policy classification.
	 * @param bool   $expectedStore          Whether diagnostic state may be stored.
	 */
	public function testRestrictiveDirectivesHaveZeroReusableFreshness(
		string $directive,
		string $expectedClassification,
		bool $expectedStore
	): void {
		$result = FreshnessPolicy::evaluate(
			array( 'cache-control' => array( 'max-age=3600, ' . $directive ) ),
			1000,
			1000,
			1000
		);

		self::assertSame( $expectedClassification, $result['classification'] );
		self::assertSame( 1000, $result['fresh_until'] );
		self::assertSame( 0, $result['current_age'] );
		self::assertFalse( $result['reusable'] );
		self::assertSame( $expectedStore, $result['store'] );
	}

	/**
	 * Verifies already-expired valid freshness is stale rather than fallback.
	 *
	 * @since 0.1.0
	 */
	public function testAlreadyExpiredValidLifetimeIsStale(): void {
		$result = FreshnessPolicy::evaluate(
			array( 'cache-control' => array( 'max-age=60' ) ),
			1000,
			1000,
			1060
		);

		self::assertSame( 'stale', $result['classification'] );
		self::assertSame( 1060, $result['fresh_until'] );
		self::assertSame( 60, $result['current_age'] );
		self::assertFalse( $result['reusable'] );
		self::assertTrue( $result['store'] );
	}

	/**
	 * Verifies freshness is reusable only while now is strictly before expiry.
	 *
	 * @since 0.1.0
	 *
	 * @dataProvider boundaryInstantProvider
	 *
	 * @param int    $now                    Current wall-clock second.
	 * @param string $expectedClassification Expected policy classification.
	 * @param bool   $expectedReusable       Whether the snapshot is reusable.
	 */
	public function testUsesAnExclusiveFreshUntilBoundary(
		int $now,
		string $expectedClassification,
		bool $expectedReusable
	): void {
		$result = FreshnessPolicy::evaluate(
			array( 'cache-control' => array( 'max-age=60' ) ),
			1000,
			1000,
			$now
		);

		self::assertSame( 1060, $result['fresh_until'] );
		self::assertSame( $expectedClassification, $result['classification'] );
		self::assertSame( $expectedReusable, $result['reusable'] );
	}

	/**
	 * Provides max-age cap cases.
	 *
	 * @since 0.1.0
	 *
	 * @return iterable<string, array{string, int}> Cases.
	 */
	public function maxAgeProvider(): iterable {
		yield 'shorter lifetime' => array( '60', 1060 );
		yield 'exact cap' => array( '3600', 4600 );
		yield 'above cap' => array( '7200', 4600 );
		yield 'quoted delta seconds' => array( '"60"', 1060 );
	}

	/**
	 * Provides lower or absent Age fields.
	 *
	 * @return iterable<string, array{array<string, list<string>>}> Cases.
	 */
	public function lowerAgeProvider(): iterable {
		yield 'lower Age' => array( array( 'age' => array( '10' ) ) );
		yield 'absent Age' => array( array() );
	}

	/**
	 * Provides unusable freshness metadata.
	 *
	 * @return iterable<string, array{array<string, list<string>>}> Cases.
	 */
	public function unusableFreshnessProvider(): iterable {
		yield 'malformed max-age' => array( array( 'cache-control' => array( 'max-age=abc' ) ) );
		yield 'negative max-age' => array( array( 'cache-control' => array( 'max-age=-1' ) ) );
		yield 'overflowed max-age' => array( array( 'cache-control' => array( 'max-age=999999999999999999999999' ) ) );
		yield 'repeated max-age fields' => array( array( 'cache-control' => array( 'max-age=60', 'max-age=60' ) ) );
		yield 'conflicting max-age fields' => array( array( 'cache-control' => array( 'max-age=60', 'max-age=120' ) ) );
		yield 'conflicting single field' => array( array( 'cache-control' => array( 'max-age=60, max-age=120' ) ) );
		yield 'Expires without Date' => array( array( 'expires' => array( self::httpDate( 1600 ) ) ) );
		yield 'malformed Date' => array(
			array(
				'date'    => array( 'not-a-date' ),
				'expires' => array( self::httpDate( 1600 ) ),
			),
		);
		yield 'repeated Date' => array(
			array(
				'date'    => array( self::httpDate( 1000 ), self::httpDate( 1000 ) ),
				'expires' => array( self::httpDate( 1600 ) ),
			),
		);
		yield 'malformed Age' => array(
			array(
				'cache-control' => array( 'max-age=60' ),
				'age'           => array( 'invalid' ),
			),
		);
		yield 'repeated Age' => array(
			array(
				'cache-control' => array( 'max-age=60' ),
				'age'           => array( '1', '1' ),
			),
		);
	}

	/**
	 * Provides restrictive directives.
	 *
	 * @return iterable<string, array{string, string, bool}> Cases.
	 */
	public function restrictiveDirectiveProvider(): iterable {
		yield 'no-cache' => array( 'no-cache', 'no_cache', true );
		yield 'no-store' => array( 'no-store', 'no_store', false );
		yield 'both directives' => array( 'no-cache, no-store', 'no_store', false );
	}

	/**
	 * Provides exact freshness-boundary instants.
	 *
	 * @return iterable<string, array{int, string, bool}> Cases.
	 */
	public function boundaryInstantProvider(): iterable {
		yield 'one second before' => array( 1059, 'fresh', true );
		yield 'at boundary' => array( 1060, 'stale', false );
		yield 'one second after' => array( 1061, 'stale', false );
	}

	/**
	 * Formats one independently fixed HTTP-date value.
	 *
	 * @param int $timestamp Unix timestamp.
	 * @return string IMF-fixdate.
	 */
	private static function httpDate( int $timestamp ): string {
		return gmdate( 'D, d M Y H:i:s \G\M\T', $timestamp );
	}
}
