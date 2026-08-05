<?php
/**
 * Slice 0 CIMD authorization and credential-isolation tests.
 *
 * @package GalatanOvidiu\Charter
 */

declare(strict_types=1);

namespace GalatanOvidiu\Charter\Tests\Integration\CimdOutboundSafety;

use GalatanOvidiu\Charter\Tests\Prototype\CimdOutboundSafety\AuthorizationBoundary;
use GalatanOvidiu\Charter\Tests\Prototype\CimdOutboundSafety\CredentialPathProbe;
use PHPUnit\Framework\TestCase;

/**
 * Proves that mutable CIMD controls only future authorization metadata.
 *
 * @since 0.1.0
 */
final class AuthorizationBoundaryTest extends TestCase {

	/**
	 * Verifies a present redirect in a fresh snapshot creates a transaction locally.
	 *
	 * @since 0.1.0
	 */
	public function testFreshPresentRedirectCreatesTransactionWithZeroOutbound(): void {
		$boundary = new AuthorizationBoundary( self::unexpectedValidator() );
		$boundary->seedValidatedSnapshot(
			self::clientId(),
			array( self::redirectA() ),
			self::fingerprintA(),
			2000
		);
		$boundary->recordConsent( self::clientId(), self::fingerprintA() );

		$result = $boundary->authorize( self::clientId(), self::redirectA(), 1999 );

		self::assertSame( 'transaction_created', $result['classification'] );
		self::assertTrue( $result['transaction_created'] );
		self::assertTrue( $result['consent_reusable'] );
		self::assertTrue( $result['snapshot_authoritative'] );
		self::assertFalse( $result['stale_fallback_used'] );
		self::assertSame( self::zeroCounters(), $result['cimd_counters'] );
	}

	/**
	 * Verifies a redirect absent from a fresh snapshot is rejected locally.
	 *
	 * @since 0.1.0
	 */
	public function testFreshAbsentRedirectRejectsLocallyWithZeroOutbound(): void {
		$boundary = new AuthorizationBoundary( self::unexpectedValidator() );
		$boundary->seedValidatedSnapshot(
			self::clientId(),
			array( self::redirectA() ),
			self::fingerprintA(),
			2000
		);

		$result = $boundary->authorize( self::clientId(), self::redirectB(), 1999 );

		self::assertSame( 'local_reject', $result['classification'] );
		self::assertFalse( $result['transaction_created'] );
		self::assertFalse( $result['consent_reusable'] );
		self::assertTrue( $result['snapshot_authoritative'] );
		self::assertFalse( $result['stale_fallback_used'] );
		self::assertSame( self::zeroCounters(), $result['cimd_counters'] );
	}

	/**
	 * Verifies an absent snapshot is validated synchronously before transaction creation.
	 *
	 * @since 0.1.0
	 */
	public function testAbsentSnapshotValidatesSynchronouslyBeforeCreatingTransaction(): void {
		$events    = array();
		$validator = static function ( string $clientId, int $now ) use ( &$events ): array {
			$events[] = 'validate';

			return self::validatedSnapshot(
				$clientId,
				array( self::redirectA() ),
				self::fingerprintA(),
				$now + 300
			);
		};
		$boundary  = new AuthorizationBoundary( $validator );

		$result   = $boundary->authorize( self::clientId(), self::redirectA(), 1000 );
		$events[] = $result['transaction_created'] ? 'transaction' : 'no_transaction';

		self::assertSame( array( 'validate', 'transaction' ), $events );
		self::assertSame( 'transaction_created', $result['classification'] );
		self::assertTrue( $result['transaction_created'] );
		self::assertFalse( $result['consent_reusable'] );
		self::assertTrue( $result['snapshot_authoritative'] );
		self::assertSame( self::oneFetchCounters(), $result['cimd_counters'] );
	}

	/**
	 * Verifies initial validation failure creates no transaction or authoritative state.
	 *
	 * @since 0.1.0
	 */
	public function testAbsentSnapshotFailureAbortsWithoutNegativeCacheAuthority(): void {
		$validations = 0;
		$validator   = static function () use ( &$validations ): array {
			++$validations;

			return self::failedValidation();
		};
		$boundary    = new AuthorizationBoundary( $validator );

		$first  = $boundary->authorize( self::clientId(), self::redirectA(), 1000 );
		$second = $boundary->authorize( self::clientId(), self::redirectA(), 1001 );

		self::assertSame( 2, $validations, 'A failed validation must not create a negative cache entry.' );
		self::assertSame( 'validation_failed', $first['classification'] );
		self::assertSame( 'validation_failed', $second['classification'] );
		self::assertFalse( $first['transaction_created'] );
		self::assertFalse( $first['snapshot_authoritative'] );
		self::assertFalse( $first['stale_fallback_used'] );
		self::assertSame( self::oneFetchCounters(), $first['cimd_counters'] );
		self::assertSame( 'absent', $boundary->snapshotState( self::clientId() )['classification'] );
	}

	/**
	 * Verifies no-store is authoritative only for the current authorization and
	 * leaves no snapshot, redirect, fingerprint, or document-shaped state.
	 */
	public function testNoStoreUsesEphemeralValidationAndLeavesNoState(): void {
		$validations = 0;
		$validator   = static function ( string $clientId, int $now ) use ( &$validations ): array {
			++$validations;
			return self::validatedSnapshot(
				$clientId,
				array( self::redirectA() ),
				self::fingerprintA(),
				$now,
				false,
				false,
				'no_store'
			);
		};
		$boundary    = new AuthorizationBoundary( $validator );

		$first  = $boundary->authorize( self::clientId(), self::redirectA(), 1000 );
		$second = $boundary->authorize( self::clientId(), self::redirectA(), 1001 );
		$state  = $boundary->snapshotState( self::clientId() );

		self::assertSame( 2, $validations );
		self::assertTrue( $first['transaction_created'] );
		self::assertTrue( $second['transaction_created'] );
		self::assertTrue( $first['snapshot_authoritative'] );
		self::assertSame( 'absent', $state['classification'] );
		self::assertSame( 0, $state['redirect_count'] );
		self::assertSame( 'none', $state['fingerprint'] );
	}

	/**
	 * Verifies no-cache may retain only a diagnostic fingerprint and always
	 * requires another complete 200 validation.
	 */
	public function testNoCacheRetainsNoAuthoritativeRedirectSetAndRevalidatesEveryTime(): void {
		$validations = 0;
		$validator   = static function ( string $clientId, int $now ) use ( &$validations ): array {
			++$validations;
			return self::validatedSnapshot(
				$clientId,
				array( self::redirectA() ),
				self::fingerprintA(),
				$now,
				false,
				true,
				'no_cache'
			);
		};
		$boundary    = new AuthorizationBoundary( $validator );

		$first = $boundary->authorize( self::clientId(), self::redirectA(), 1000 );
		$state = $boundary->snapshotState( self::clientId() );
		$next  = $boundary->authorize( self::clientId(), self::redirectA(), 1001 );

		self::assertSame( 2, $validations );
		self::assertTrue( $first['transaction_created'] );
		self::assertTrue( $next['transaction_created'] );
		self::assertSame( 'diagnostic', $state['classification'] );
		self::assertSame( 0, $state['redirect_count'] );
		self::assertSame( self::fingerprintA(), $state['fingerprint'] );
	}

	/**
	 * Verifies stale metadata is replaced before a transaction can use it.
	 *
	 * @since 0.1.0
	 */
	public function testStaleSnapshotRequiresCompleteSynchronousReplacement(): void {
		$validator = static function ( string $clientId, int $now ): array {
			return self::validatedSnapshot(
				$clientId,
				array( self::redirectB() ),
				self::fingerprintB(),
				$now + 300
			);
		};
		$boundary  = new AuthorizationBoundary( $validator );
		$boundary->seedValidatedSnapshot(
			self::clientId(),
			array( self::redirectA() ),
			self::fingerprintA(),
			1000
		);
		$boundary->recordConsent( self::clientId(), self::fingerprintA() );

		$result = $boundary->authorize( self::clientId(), self::redirectB(), 1000 );

		self::assertSame( 'transaction_created', $result['classification'] );
		self::assertTrue( $result['transaction_created'] );
		self::assertFalse( $result['consent_reusable'] );
		self::assertTrue( $result['snapshot_authoritative'] );
		self::assertFalse( $result['stale_fallback_used'] );
		self::assertSame( self::oneFetchCounters(), $result['cimd_counters'] );
	}

	/**
	 * Verifies changed redirects invalidate consent reuse without revoking credentials.
	 *
	 * @since 0.1.0
	 */
	public function testRedirectChangeRequiresFreshConsentWithoutDisturbingCredentials(): void {
		$credentials = CredentialPathProbe::forEstablishedAuthorization( self::clientId(), static fn (): bool => true );
		$before      = $credentials->state();
		$validator   = static function ( string $clientId, int $now ): array {
			return self::validatedSnapshot(
				$clientId,
				array( self::redirectB() ),
				self::fingerprintB(),
				$now + 300
			);
		};
		$boundary    = new AuthorizationBoundary( $validator );
		$boundary->seedValidatedSnapshot(
			self::clientId(),
			array( self::redirectA() ),
			self::fingerprintA(),
			1000
		);
		$boundary->recordConsent( self::clientId(), self::fingerprintA() );

		$result = $boundary->authorize( self::clientId(), self::redirectB(), 1000 );

		self::assertTrue( $result['transaction_created'] );
		self::assertFalse( $result['consent_reusable'] );
		self::assertSame( $before, $credentials->state() );
		self::assertSame(
			array(
				'grant_active'          => true,
				'access_active'         => true,
				'refresh_family_active' => true,
				'refresh_generation'    => 1,
			),
			$credentials->state()
		);
	}

	/**
	 * Verifies stale validation failure never authorizes from stale state.
	 *
	 * @since 0.1.0
	 */
	public function testStaleValidationFailureAbortsWithoutStaleFallback(): void {
		$boundary = new AuthorizationBoundary( static fn (): array => self::failedValidation() );
		$boundary->seedValidatedSnapshot(
			self::clientId(),
			array( self::redirectA() ),
			self::fingerprintA(),
			1000
		);

		$result = $boundary->authorize( self::clientId(), self::redirectA(), 1000 );

		self::assertSame( 'validation_failed', $result['classification'] );
		self::assertFalse( $result['transaction_created'] );
		self::assertFalse( $result['snapshot_authoritative'] );
		self::assertFalse( $result['stale_fallback_used'] );
		self::assertSame( self::oneFetchCounters(), $result['cimd_counters'] );
		self::assertSame( 'diagnostic', $boundary->snapshotState( self::clientId() )['classification'] );
		self::assertSame( 0, $boundary->snapshotState( self::clientId() )['redirect_count'] );
	}

	/**
	 * Verifies every established credential-use path remains local during outage.
	 *
	 * @since 0.1.0
	 */
	public function testCredentialPathsRemainLocalWhileTheCimdOriginIsUnavailable(): void {
		$boundary    = new AuthorizationBoundary( static fn (): array => self::failedValidation() );
		$credentials = CredentialPathProbe::forEstablishedAuthorization( self::clientId(), static fn (): bool => true );
		$before      = $credentials->state();

		$failedAuthorization = $boundary->authorize( self::clientId(), self::redirectA(), 1000 );
		$results             = array(
			'code_exchanged'              => $credentials->exchangeCode(),
			'refresh_rotated'             => $credentials->refresh(),
			'access_validated'            => $credentials->validateAccess(),
			'protected_request_completed' => $credentials->dispatchProtectedRequest(),
		);

		self::assertSame( 'validation_failed', $failedAuthorization['classification'] );

		foreach ( $results as $classification => $result ) {
			self::assertSame( $classification, $result['classification'] );
			self::assertSame( self::zeroCounters(), $result['cimd_counters'] );
			self::assertFalse( $result['credential_disturbed'] );
		}

		$after = $credentials->state();
		self::assertTrue( $after['grant_active'] );
		self::assertTrue( $after['access_active'] );
		self::assertTrue( $after['refresh_family_active'] );
		self::assertSame( $before['refresh_generation'] + 1, $after['refresh_generation'] );
	}

	/**
	 * Returns a validator that fails the test if fresh/local behavior calls it.
	 *
	 * @return callable(string, int): array<string, mixed> Validator.
	 */
	private static function unexpectedValidator(): callable {
		return static function (): array {
			self::fail( 'A fresh snapshot must not invoke CIMD validation.' );
		};
	}

	/**
	 * Creates one successful synchronous validation result.
	 *
	 * @param string        $clientId    Exact Client Identifier.
	 * @param array<string> $redirects  Exact redirect set.
	 * @param string        $fingerprint Document fingerprint.
	 * @param int           $freshUntil  Exclusive freshness boundary.
	 * @param bool          $reusable           Whether the result may be reused.
	 * @param bool          $store              Whether diagnostic state may remain.
	 * @param string        $cacheClassification Stable cache classification.
	 * @return array<string, mixed> Validation result.
	 */
	private static function validatedSnapshot(
		string $clientId,
		array $redirects,
		string $fingerprint,
		int $freshUntil,
		bool $reusable = true,
		bool $store = true,
		string $cacheClassification = 'fresh'
	): array {
		return array(
			'classification'       => 'validated',
			'client_id'            => $clientId,
			'redirect_uris'        => $redirects,
			'fingerprint'          => $fingerprint,
			'fresh_until'          => $freshUntil,
			'reusable'             => $reusable,
			'store'                => $store,
			'cache_classification' => $cacheClassification,
			'cimd_counters'        => self::oneFetchCounters(),
		);
	}

	/**
	 * Creates one failed synchronous validation result.
	 *
	 * @return array<string, mixed> Failure result.
	 */
	private static function failedValidation(): array {
		return array(
			'classification' => 'failed',
			'client_id'      => self::clientId(),
			'redirect_uris'  => array(),
			'fingerprint'    => 'none',
			'fresh_until'    => 0,
			'cimd_counters'  => self::oneFetchCounters(),
		);
	}

	/**
	 * Returns zero observable CIMD activity.
	 *
	 * @return array{dns:int, tcp:int, tls:int, http:int} Counters.
	 */
	private static function zeroCounters(): array {
		return array(
			'dns'  => 0,
			'tcp'  => 0,
			'tls'  => 0,
			'http' => 0,
		);
	}

	/**
	 * Returns one complete successful validation operation.
	 *
	 * @return array{dns:int, tcp:int, tls:int, http:int} Counters.
	 */
	private static function oneFetchCounters(): array {
		return array(
			'dns'  => 2,
			'tcp'  => 1,
			'tls'  => 1,
			'http' => 1,
		);
	}

	/**
	 * Returns the canonical test Client Identifier.
	 *
	 * @return string Client Identifier.
	 */
	private static function clientId(): string {
		return 'https://client.example/metadata';
	}

	/**
	 * Returns the first canonical redirect URI.
	 *
	 * @return string Redirect URI.
	 */
	private static function redirectA(): string {
		return 'https://client.example/callback-a';
	}

	/**
	 * Returns the second canonical redirect URI.
	 *
	 * @return string Redirect URI.
	 */
	private static function redirectB(): string {
		return 'https://client.example/callback-b';
	}

	/**
	 * Returns the first canonical document fingerprint.
	 *
	 * @return string SHA-256-shaped fingerprint.
	 */
	private static function fingerprintA(): string {
		return str_repeat( 'a', 64 );
	}

	/**
	 * Returns the second canonical document fingerprint.
	 *
	 * @return string SHA-256-shaped fingerprint.
	 */
	private static function fingerprintB(): string {
		return str_repeat( 'b', 64 );
	}
}
