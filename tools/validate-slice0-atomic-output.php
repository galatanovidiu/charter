<?php
/**
 * Validates and redacts captured Slice 0 P1 NDJSON evidence.
 *
 * @package GalatanOvidiu\Charter
 */

declare(strict_types=1);

namespace GalatanOvidiu\Charter\Tools;

use GalatanOvidiu\Charter\Tests\Fixtures\AtomicLifecycle\HarnessContract;
use GalatanOvidiu\Charter\Tests\Fixtures\AtomicLifecycle\SanitizedResult;
use JsonException;
use RuntimeException;
use SplFileObject;
use Throwable;

require_once dirname( __DIR__ ) . '/tests/fixtures/atomic-lifecycle/HarnessContract.php';
require_once dirname( __DIR__ ) . '/tests/fixtures/atomic-lifecycle/LaneConfiguration.php';
require_once dirname( __DIR__ ) . '/tests/fixtures/atomic-lifecycle/SanitizedResult.php';

// phpcs:disable Generic.Commenting.DocComment.MissingShort, Squiz.Commenting -- Standalone evidence-gate internals are constrained by one fixed CLI contract.
// phpcs:disable WordPress.Security.EscapeOutput.OutputNotEscaped -- Every output is fixed or already validated and redacted.

/**
 * Rejects unexpected output and writes only marker-redacted evidence.
 */
final class ValidateSlice0AtomicOutput {

	private const MAXIMUM_INPUT_BYTES = 10485760;

	private const MAXIMUM_RECORDS = 160;

	/**
	 * @param string $ndjsonPath Captured matrix standard output.
	 * @param string $stderrPath Captured matrix standard error.
	 * @param string $artifactSha256 Expected pre-P1 artifact checksum.
	 * @param string $redactedPath Destination for validated redacted evidence.
	 */
	public static function run(
		string $ndjsonPath,
		string $stderrPath,
		string $artifactSha256,
		string $redactedPath
	): void {
		if (
			! is_file( $ndjsonPath )
			|| ! is_file( $stderrPath )
			|| 0 !== filesize( $stderrPath )
			|| ! preg_match( '/^[a-f0-9]{64}$/D', $artifactSha256 )
			|| realpath( $ndjsonPath ) === realpath( $redactedPath )
		) {
			throw new RuntimeException( 'Atomic evidence input contract failed.' );
		}

		$inputSize = filesize( $ndjsonPath );
		if ( false === $inputSize || 0 === $inputSize || self::MAXIMUM_INPUT_BYTES < $inputSize ) {
			throw new RuntimeException( 'Atomic evidence input size failed.' );
		}

		$expectedCases = array_merge( HarnessContract::cases(), array( HarnessContract::CASE_CLEANUP ) );
		$laneCases     = array();
		$redactedLines = array();
		$input         = new SplFileObject( $ndjsonPath, 'r' );
		$recordCount   = 0;

		while ( ! $input->eof() ) {
			$line = $input->fgets();
			if ( '' === $line ) {
				continue;
			}

			$line = rtrim( $line, "\r\n" );
			if ( '' === $line || 16384 < strlen( $line ) || self::MAXIMUM_RECORDS < ++$recordCount ) {
				throw new RuntimeException( 'Atomic evidence line contract failed.' );
			}

			try {
				$decoded = json_decode( $line, true, 8, JSON_THROW_ON_ERROR );
			} catch ( JsonException ) {
				throw new RuntimeException( 'Atomic evidence JSON contract failed.' );
			}

			if ( ! is_array( $decoded ) ) {
				throw new RuntimeException( 'Atomic evidence record was not an object.' );
			}

			$record = array();
			foreach ( $decoded as $key => $value ) {
				if ( is_string( $key ) ) {
					$record[ $key ] = $value;
				}
			}

			if (
				! SanitizedResult::validate( $record )
				|| true !== $record['passed']
				|| HarnessContract::OUTCOME_PASSED !== $record['status']
				|| $artifactSha256 !== $record['artifact_sha256']
			) {
				throw new RuntimeException( 'Atomic evidence detailed result failed.' );
			}

			$family    = $record['database_family'];
			$version   = $record['database_version'];
			$isolation = $record['isolation'];
			$caseId    = $record['case_id'];

			if ( ! is_string( $family ) || ! is_string( $version ) || ! is_string( $isolation ) || ! is_string( $caseId ) ) {
				throw new RuntimeException( 'Atomic evidence lane/case types failed.' );
			}

			$laneKey = $family . '|' . $version . '|' . $isolation;

			if ( isset( $laneCases[ $laneKey ][ $caseId ] ) ) {
				throw new RuntimeException( 'Atomic evidence lane/case identity failed.' );
			}

			if ( HarnessContract::CASE_PREFLIGHT === $caseId && '' === $record['sql_mode'] ) {
				throw new RuntimeException( 'Atomic evidence SQL mode was absent.' );
			}

			$laneCases[ $laneKey ][ $caseId ] = true;
			$record['database_image_digest']  = '[DATABASE_IMAGE_DIGEST]';
			$record['artifact_sha256']        = '[ARTIFACT_SHA256]';

			try {
				// phpcs:ignore WordPress.WP.AlternativeFunctions.json_encode_json_encode -- WordPress is intentionally absent from the standalone evidence gate.
				$redactedLines[] = json_encode( $record, JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES );
			} catch ( JsonException ) {
				throw new RuntimeException( 'Atomic redacted evidence encoding failed.' );
			}
		}

		$expectedLanes = array();
		foreach ( HarnessContract::databaseMatrix() as $lane ) {
			$expectedLanes[] = $lane['family'] . '|' . $lane['version'] . '|' . $lane['isolation'];
		}
		sort( $expectedLanes );
		$observedLanes = array_keys( $laneCases );
		sort( $observedLanes );

		if ( $expectedLanes !== $observedLanes ) {
			throw new RuntimeException( 'Atomic evidence matrix was incomplete.' );
		}

		foreach ( $laneCases as $cases ) {
			$observedCases = array_keys( $cases );
			sort( $observedCases );
			$sortedExpectedCases = $expectedCases;
			sort( $sortedExpectedCases );

			if ( $sortedExpectedCases !== $observedCases ) {
				throw new RuntimeException( 'Atomic evidence case set was incomplete.' );
			}
		}

		$redacted = implode( "\n", $redactedLines ) . "\n";
		self::assertGenericScanPasses( $redacted );
		self::writeExactOutput( $redactedPath, $redacted );
	}

	private static function assertGenericScanPasses( string $redacted ): void {
		$forbidden = array(
			'/Authorization:/i',
			'/Bearer\s/i',
			'/charter-p1-[a-z0-9_-]*material/i',
			'/charter_p1_worker/i',
			'/(?<![a-f0-9])[a-f0-9]{64,}(?![a-f0-9])/i',
			'/(?<![A-Za-z0-9+\/])[A-Za-z0-9+\/]{80,}={0,2}(?![A-Za-z0-9+\/])/',
		);

		foreach ( $forbidden as $pattern ) {
			if ( preg_match( $pattern, $redacted ) ) {
				throw new RuntimeException( 'Atomic evidence generic secret scan failed.' );
			}
		}
	}

	private static function writeExactOutput( string $path, string $contents ): void {
		$directory = dirname( $path );
		if ( ! is_dir( $directory ) || is_link( $path ) ) {
			throw new RuntimeException( 'Atomic redacted evidence destination was unsafe.' );
		}

		$temporary = $path . '.tmp-' . getmypid();
		// phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_file_put_contents -- Writes one runner-owned validated evidence file.
		$written = file_put_contents( $temporary, $contents, LOCK_EX );
		// phpcs:ignore WordPress.WP.AlternativeFunctions.rename_rename -- Atomically promotes one runner-owned validated evidence file.
		if ( strlen( $contents ) !== $written || ! rename( $temporary, $path ) ) {
			throw new RuntimeException( 'Atomic redacted evidence could not be written.' );
		}
	}
}

$arguments = $_SERVER['argv'] ?? array();

try {
	if ( ! is_array( $arguments ) || 5 !== count( $arguments ) ) {
		throw new RuntimeException( 'Atomic evidence arguments were incomplete.' );
	}

	foreach ( $arguments as $argument ) {
		if ( ! is_string( $argument ) ) {
			throw new RuntimeException( 'Atomic evidence argument was invalid.' );
		}
	}

	ValidateSlice0AtomicOutput::run( $arguments[1], $arguments[2], $arguments[3], $arguments[4] );
	echo '{"schema_version":1,"record_type":"evidence_validation","status":"passed","passed":true}' . "\n";
} catch ( Throwable ) {
	echo '{"schema_version":1,"record_type":"evidence_validation","status":"failed","passed":false}' . "\n";
	exit( 1 );
}
