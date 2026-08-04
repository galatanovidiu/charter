<?php
/**
 * Slice 0 atomic-lifecycle sanitized-output integration tests.
 *
 * @package GalatanOvidiu\Charter
 */

declare(strict_types=1);

namespace GalatanOvidiu\Charter\Tests\Integration\AtomicLifecycle;

use GalatanOvidiu\Charter\Tests\Fixtures\AtomicLifecycle\HarnessContract;
use GalatanOvidiu\Charter\Tests\Fixtures\AtomicLifecycle\LaneConfiguration;
use GalatanOvidiu\Charter\Tests\Fixtures\AtomicLifecycle\SanitizedResult;
use PHPUnit\Framework\TestCase;

require_once dirname( __DIR__, 2 ) . '/fixtures/atomic-lifecycle/HarnessContract.php';
require_once dirname( __DIR__, 2 ) . '/fixtures/atomic-lifecycle/LaneConfiguration.php';
require_once dirname( __DIR__, 2 ) . '/fixtures/atomic-lifecycle/SanitizedResult.php';

/**
 * Proves that the public harness output is fixed-schema and secret-safe.
 *
 * @since 0.1.0
 */
final class SanitizedOutputTest extends TestCase {

	/**
	 * Verifies that the exact two approved checksum fields remain usable.
	 *
	 * @since 0.1.0
	 */
	public function testValidatedChecksumsAreTheOnlyApprovedLongHexadecimalValues(): void {
		$result = SanitizedResult::base(
			self::lane(),
			HarnessContract::CASE_PREFLIGHT,
			HarnessContract::DEFAULT_WORKERS,
			1
		);

		self::assertTrue( SanitizedResult::validate( $result ) );
		$encoded = SanitizedResult::encode( $result );

		self::assertStringNotContainsString( 'proof-user', $encoded );
		self::assertStringNotContainsString( 'private-value-never-rendered', $encoded );
		self::assertStringNotContainsString( 'Authorization:', $encoded );
		self::assertStringNotContainsString( 'Bearer ', $encoded );
		$databaseDigest = $result['database_image_digest'] ?? null;
		$artifactDigest = $result['artifact_sha256'] ?? null;

		if ( ! is_string( $databaseDigest ) || ! is_string( $artifactDigest ) ) {
			self::fail( 'The validated checksum fields were not strings.' );
		}

		$genericScanInput = str_replace(
			array(
				$databaseDigest,
				$artifactDigest,
			),
			array( '<validated-database-digest>', '<validated-artifact-checksum>' ),
			$encoded
		);

		self::assertDoesNotMatchRegularExpression(
			'/(?<![a-f0-9])[a-f0-9]{64,}(?![a-f0-9])/i',
			$genericScanInput
		);
		self::assertDoesNotMatchRegularExpression(
			'/(?<![A-Za-z0-9+\\/])[A-Za-z0-9+\\/]{80,}={0,2}(?![A-Za-z0-9+\\/])/',
			$genericScanInput
		);

		$result['database_version'] = str_repeat( 'c', 64 );

		self::assertFalse(
			SanitizedResult::validate( $result ),
			'An unapproved long hexadecimal value escaped through a public evidence field.'
		);
	}

	/**
	 * Verifies that proof credentials and Authorization headers never escape.
	 *
	 * @since 0.1.0
	 *
	 * @dataProvider forbiddenOutputProvider
	 *
	 * @param string $unsafeValue Secret-like output value.
	 */
	public function testSecretLikeOutputIsRejected( string $unsafeValue ): void {
		$result                     = SanitizedResult::base(
			self::lane(),
			HarnessContract::CASE_CODE_EXCHANGE,
			1,
			1
		);
		$result['database_version'] = $unsafeValue;

		self::assertFalse( SanitizedResult::validate( $result ) );
		self::assertSame(
			SanitizedResult::opaqueFailure(),
			json_decode( SanitizedResult::encode( $result ), true, 512, JSON_THROW_ON_ERROR ),
			'Invalid output copied unsafe input into the opaque failure record.'
		);
	}

	/**
	 * Verifies that unknown fields cannot widen the public evidence schema.
	 *
	 * @since 0.1.0
	 */
	public function testUnknownAndExplicitlyForbiddenFieldsAreRejected(): void {
		$result                         = SanitizedResult::base(
			self::lane(),
			HarnessContract::CASE_CODE_REPLAY,
			1,
			1
		);
		$result['authorization_header'] = 'redacted';

		self::assertFalse( SanitizedResult::validate( $result ) );

		unset( $result['authorization_header'] );
		$result['unexpected'] = false;

		self::assertFalse( SanitizedResult::validate( $result ) );
	}

	/**
	 * Verifies the matrix and scenario lists remain exactly bounded by the plan.
	 *
	 * @since 0.1.0
	 */
	public function testMatrixAndBehaviorCasesAreFiniteAndComplete(): void {
		$matrix = HarnessContract::databaseMatrix();
		$cases  = HarnessContract::cases();

		self::assertCount( 8, $matrix );
		self::assertSame(
			array(
				'preflight',
				'code_exchange',
				'code_race',
				'code_replay',
				'code_worker_death',
				'code_commit_ambiguity',
				'refresh_rotation',
				'refresh_race',
				'refresh_ancestor_replay',
				'deadlock_recovery',
				'lock_timeout_recovery',
				'connection_loss_boundary',
			),
			$cases
		);
		self::assertSame(
			array( 'REPEATABLE READ', 'READ COMMITTED' ),
			array_values( array_unique( array_column( $matrix, 'isolation' ) ) )
		);
		self::assertSame(
			array( 'mysql:8.0.46', 'mysql:8.4.11', 'mariadb:10.11.18', 'mariadb:12.3.2' ),
			array_values( array_unique( array_column( $matrix, 'image' ) ) )
		);
	}

	/**
	 * Supplies fixed examples that must not leave the harness.
	 *
	 * @return iterable<string, array{string}>
	 */
	public function forbiddenOutputProvider(): iterable {
		yield 'authorization header' => array( 'Authorization: Bearer fixture' );
		yield 'code material' => array( 'charter-p1-code-material' );
		yield 'actual primary code material' => array( 'charter-p1-primary-code-proof-material' );
		yield 'actual unknown code material' => array( 'charter-p1-unknown-code-proof-material' );
		yield 'access material' => array( 'charter-p1-access-material' );
		yield 'refresh material' => array( 'charter-p1-refresh-material' );
		yield 'root material' => array( 'charter-p1-root-material' );
		yield 'derived material' => array( 'charter-p1-derived-material' );
		yield 'long base64-like material' => array( str_repeat( 'Q', 80 ) );
	}

	/**
	 * Creates a non-secret lane used only to exercise the result contract.
	 *
	 * @since 0.1.0
	 */
	private static function lane(): LaneConfiguration {
		return new LaneConfiguration(
			'disposable-database',
			3306,
			'charter_p1_proof',
			'proof-user',
			'private-value-never-rendered',
			'mysql',
			'8.0.46',
			'sha256:' . str_repeat( 'a', 64 ),
			'REPEATABLE READ',
			null,
			str_repeat( 'b', 64 )
		);
	}
}
