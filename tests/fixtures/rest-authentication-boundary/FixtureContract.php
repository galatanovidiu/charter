<?php
/**
 * Fixed secret-safe contracts for the disposable Slice 0 P2 runners.
 *
 * @package GalatanOvidiu\Charter
 */

declare(strict_types=1);

namespace GalatanOvidiu\Charter\Tests\Fixtures\RestAuthenticationBoundary;

/**
 * Creates and validates the only records the P2 runners may emit.
 */
final class FixtureContract {

	public const SCHEMA_VERSION = 1;

	public const PROCESS_RECORD_TYPE = 'rest_authentication_boundary_process_matrix';

	public const HTTP_RECORD_TYPE = 'rest_authentication_boundary_http_matrix';

	/**
	 * Exact process-runner check keys.
	 *
	 * @var list<string>
	 */
	private const PROCESS_CHECK_KEYS = array(
		'wordpress_6_9',
		'fresh_bearer_only_succeeded',
		'fresh_mixed_rejected_400',
		'fresh_mixed_validation_suppressed',
		'fresh_mixed_callbacks_suppressed',
		'fresh_mixed_identity_unchanged',
		'fresh_public_mixed_inert',
		'fresh_error_matrix',
		'fresh_legacy_only_preserved',
		'fresh_route_matrix',
		'fresh_direct_served_direct',
		'fresh_cleanup_matrix',
		'reused_full_matrix',
		'context_depth_zero',
		'unexpected_output_suppressed',
		'all_processes_terminated',
		'exact_cleanup_complete',
	);

	/**
	 * Exact HTTP-runner check keys.
	 *
	 * @var list<string>
	 */
	private const HTTP_CHECK_KEYS = array(
		'wordpress_6_9',
		'missing_bearer_challenge_exact',
		'invalid_bearer_challenge_exact',
		'invalid_transport_rejected_400',
		'insufficient_scope_challenge_exact',
		'oauth_cache_cors_headers_parsed',
		'valid_bearer_succeeded',
		'wordpress_permission_denial_preserved',
		'assigned_cookie_bearer_rejected_400',
		'assigned_cookie_bearer_invalid_request',
		'assigned_cookie_bearer_resource_metadata_exact',
		'assigned_cookie_bearer_disclosed_no_detail',
		'public_cookie_bearer_inert',
		'public_cookie_bearer_has_no_challenge',
		'public_headers_preserved',
		'invalid_nonce_status_preserved',
		'invalid_nonce_code_preserved',
		'invalid_nonce_has_no_bearer_challenge',
		'invalid_application_password_preserved',
		'invalid_application_password_has_no_bearer_challenge',
		'cookie_without_bearer_preserved',
		'application_password_without_bearer_preserved',
		'cookie_headers_preserved',
		'application_password_headers_preserved',
		'missing_nonce_anonymized_before_boundary',
		'missing_nonce_bearer_uses_bearer_only',
		'multi_handler_allow_exact',
		'request_timeouts_finite',
		'credentials_private',
		'exact_cleanup_complete',
	);

	/**
	 * Returns the fixed process-runner record.
	 *
	 * @param array<string, bool> $checks Candidate checks.
	 * @return array<string, mixed>
	 */
	public static function processResult( array $checks ): array {
		return self::result( self::PROCESS_RECORD_TYPE, self::PROCESS_CHECK_KEYS, $checks );
	}

	/**
	 * Returns the fixed HTTP-runner record.
	 *
	 * @param array<string, bool> $checks Candidate checks.
	 * @return array<string, mixed>
	 */
	public static function httpResult( array $checks ): array {
		return self::result( self::HTTP_RECORD_TYPE, self::HTTP_CHECK_KEYS, $checks );
	}

	/**
	 * Reports whether the disposable proof is running on the supported WordPress 6.9 line.
	 *
	 * @param mixed $version Candidate WordPress version.
	 */
	public static function isSupportedWordPressVersion( mixed $version ): bool {
		return is_string( $version ) && 1 === preg_match( '/^6\.9\.[0-9]+(?:[-+].*)?$/D', $version );
	}

	/**
	 * Returns a fixed failed process-runner record.
	 *
	 * @return array<string, mixed>
	 */
	public static function processFailure(): array {
		return self::processResult( array() );
	}

	/**
	 * Returns a fixed failed HTTP-runner record.
	 *
	 * @return array<string, mixed>
	 */
	public static function httpFailure(): array {
		return self::httpResult( array() );
	}

	/**
	 * Validates one exact runner record.
	 *
	 * @param mixed  $value       Decoded JSON value.
	 * @param string $record_type Expected record type.
	 */
	public static function isResult( mixed $value, string $record_type ): bool {
		$keys = match ( $record_type ) {
			self::PROCESS_RECORD_TYPE => self::PROCESS_CHECK_KEYS,
			self::HTTP_RECORD_TYPE    => self::HTTP_CHECK_KEYS,
			default                   => array(),
		};

		if ( array() === $keys || ! is_array( $value ) ) {
			return false;
		}

		if ( array_keys( $value ) !== array( 'schema_version', 'record_type', 'status', 'passed', 'checks' ) ) {
			return false;
		}

		if (
			self::SCHEMA_VERSION !== $value['schema_version']
			|| $record_type !== $value['record_type']
			|| ! in_array( $value['status'], array( 'passed', 'failed' ), true )
			|| ! is_bool( $value['passed'] )
			|| ! self::hasExactBooleanKeys( $value['checks'], $keys )
		) {
			return false;
		}

		$all_checks_passed = ! in_array( false, $value['checks'], true );

		return $all_checks_passed === $value['passed']
			&& ( $all_checks_passed ? 'passed' : 'failed' ) === $value['status'];
	}

	/**
	 * Creates one exact fixed-key record.
	 *
	 * @param string              $record_type Record type.
	 * @param array<string>       $keys        Ordered check keys.
	 * @param array<string, bool> $checks      Candidate checks.
	 * @return array<string, mixed>
	 */
	private static function result( string $record_type, array $keys, array $checks ): array {
		$fixed = array();

		foreach ( $keys as $key ) {
			$fixed[ $key ] = true === ( $checks[ $key ] ?? false );
		}

		$passed = ! in_array( false, $fixed, true );

		return array(
			'schema_version' => self::SCHEMA_VERSION,
			'record_type'    => $record_type,
			'status'         => $passed ? 'passed' : 'failed',
			'passed'         => $passed,
			'checks'         => $fixed,
		);
	}

	/**
	 * Checks exact keys and boolean values.
	 *
	 * @param mixed         $value Candidate map.
	 * @param array<string> $keys  Exact ordered keys.
	 */
	private static function hasExactBooleanKeys( mixed $value, array $keys ): bool {
		if ( ! is_array( $value ) || array_keys( $value ) !== $keys ) {
			return false;
		}

		foreach ( $value as $item ) {
			if ( ! is_bool( $item ) ) {
				return false;
			}
		}

		return true;
	}
}
