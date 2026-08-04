<?php
/**
 * Private child-worker protocol for the disposable Slice 0 P2 process matrix.
 *
 * @package GalatanOvidiu\Charter
 */

declare(strict_types=1);

namespace GalatanOvidiu\Charter\Tests\Fixtures\RestAuthenticationBoundary;

/**
 * Creates and validates one boolean-only child-worker result.
 */
final class WorkerContract {

	public const RECORD_TYPE = 'rest_authentication_boundary_worker';

	/**
	 * Known non-secret markers used to prove failure details stay suppressed.
	 *
	 * @var list<string>
	 */
	public const PRIVATE_FAILURE_MARKERS = array(
		'charter-p2-private-cookie-marker',
		'charter-p2-private-bearer-marker',
		'charter-p2-private-authorization-marker',
	);

	/**
	 * Exact supported worker modes.
	 *
	 * @var list<string>
	 */
	public const MODES = array(
		'bearer-only',
		'mixed',
		'public-mixed',
		'error-matrix',
		'legacy-only',
		'route-matrix',
		'direct-served-direct',
		'cleanup-matrix',
		'reused',
		'failure-output',
	);

	/**
	 * Exact worker check keys.
	 *
	 * @var list<string>
	 */
	private const CHECK_KEYS = array(
		'wordpress_6_9_5',
		'expected_response',
		'validation_count_exact',
		'callbacks_exact',
		'identity_unchanged',
		'context_depth_zero',
	);

	/**
	 * Returns one fixed worker result.
	 *
	 * @param string              $mode   Worker mode.
	 * @param array<string, bool> $checks Candidate checks.
	 * @return array<string, mixed>
	 */
	public static function result( string $mode, array $checks ): array {
		if ( ! in_array( $mode, self::MODES, true ) ) {
			$mode = 'failure-output';
		}

		$fixed = array();
		foreach ( self::CHECK_KEYS as $key ) {
			$fixed[ $key ] = true === ( $checks[ $key ] ?? false );
		}

		$passed = ! in_array( false, $fixed, true );

		return array(
			'schema_version' => FixtureContract::SCHEMA_VERSION,
			'record_type'    => self::RECORD_TYPE,
			'mode'           => $mode,
			'status'         => $passed ? 'passed' : 'failed',
			'passed'         => $passed,
			'checks'         => $fixed,
		);
	}

	/**
	 * Validates one exact worker result.
	 *
	 * @param mixed  $value Candidate decoded value.
	 * @param string $mode  Expected mode.
	 */
	public static function isResult( mixed $value, string $mode ): bool {
		if ( ! is_array( $value ) || array_keys( $value ) !== array( 'schema_version', 'record_type', 'mode', 'status', 'passed', 'checks' ) ) {
			return false;
		}

		if (
			FixtureContract::SCHEMA_VERSION !== $value['schema_version']
			|| self::RECORD_TYPE !== $value['record_type']
			|| $mode !== $value['mode']
			|| ! in_array( $value['status'], array( 'passed', 'failed' ), true )
			|| ! is_bool( $value['passed'] )
			|| ! is_array( $value['checks'] )
			|| array_keys( $value['checks'] ) !== self::CHECK_KEYS
		) {
			return false;
		}

		foreach ( $value['checks'] as $check ) {
			if ( ! is_bool( $check ) ) {
				return false;
			}
		}

		$passed = ! in_array( false, $value['checks'], true );

		return $passed === $value['passed'] && ( $passed ? 'passed' : 'failed' ) === $value['status'];
	}

	/**
	 * Prevents construction.
	 */
	private function __construct() {}
}
