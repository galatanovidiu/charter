<?php
/**
 * Fixed-schema, secret-safe output for the Slice 0 P1 harness.
 *
 * @package GalatanOvidiu\Charter
 */

declare(strict_types=1);

namespace GalatanOvidiu\Charter\Tests\Fixtures\AtomicLifecycle;

// phpcs:disable Squiz.Commenting.FunctionComment.MissingParamTag -- Fixed-schema methods are documented as a unit below.

use JsonException;

/**
 * Builds and validates the only detailed record allowed out of the harness.
 */
final class SanitizedResult {

	private const RECORD_TYPE = 'case_result';

	/**
	 * Fields whose values are numeric counts.
	 *
	 * @var list<string>
	 */
	private const COUNT_FIELDS = array(
		'workers',
		'rounds',
		'responses_successful',
		'committed_winners',
		'replays',
		'rollbacks',
		'retries',
		'deadlocks',
		'lock_timeouts',
		'connection_losses',
		'worker_deaths',
		'distinct_connections',
		'committed_code_lineages',
		'valid_code_descendants',
		'active_refresh_members',
		'active_access_credentials',
		'replay_events',
		'sentinel_residue',
		'cleanup_tables_remaining',
		'worker_processes_remaining',
	);

	/**
	 * Fields whose values are booleans.
	 *
	 * @var list<string>
	 */
	private const BOOLEAN_FIELDS = array(
		'family_terminal',
		'grant_terminal',
		'unrelated_state_unchanged',
		'sibling_domain_unchanged',
		'raw_wpdb_replayed_outside_transaction',
		'owned_connection_fail_closed',
		'constraints_enforced',
		'autocommit_initial',
		'read_write',
		'proxied',
		'replicated',
		'galera',
		'passed',
	);

	/**
	 * Output keys that may never appear at any nesting level.
	 *
	 * @var list<string>
	 */
	private const FORBIDDEN_KEYS = array(
		'authorization_header',
		'authorization_code',
		'access_token',
		'refresh_token',
		'client_secret',
		'pkce',
		'credential_digest',
		'root_key',
		'derived_key',
		'database_password',
		'connection_string',
		'raw_sql',
		'query',
		'rows',
		'error_message',
	);

	/**
	 * Known proof markers that may never reach output.
	 *
	 * @var list<string>
	 */
	private const FORBIDDEN_MARKERS = array(
		'charter-p1-code-material',
		'charter-p1-access-material',
		'charter-p1-refresh-material',
		'charter-p1-client-secret',
		'charter-p1-root-material',
		'charter-p1-derived-material',
		'Authorization:',
		'Bearer ',
	);

	/**
	 * Creates a complete result initialized to conservative values.
	 *
	 * @return array<string, mixed>
	 */
	public static function base(
		LaneConfiguration $lane,
		string $caseId,
		int $workers,
		int $rounds
	): array {
		return array(
			'schema_version' => HarnessContract::PROTOCOL_VERSION,
			'record_type'    => self::RECORD_TYPE,
			'case_id'        => $caseId,
		) + $lane->publicEvidence() + array(
			'workers'                               => $workers,
			'rounds'                                => $rounds,
			'responses_successful'                  => 0,
			'committed_winners'                     => 0,
			'replays'                               => 0,
			'rollbacks'                             => 0,
			'retries'                               => 0,
			'deadlocks'                             => 0,
			'lock_timeouts'                         => 0,
			'connection_losses'                     => 0,
			'worker_deaths'                         => 0,
			'distinct_connections'                  => 0,
			'committed_code_lineages'               => 0,
			'valid_code_descendants'                => 0,
			'active_refresh_members'                => 0,
			'active_access_credentials'             => 0,
			'replay_events'                         => 0,
			'sentinel_residue'                      => 0,
			'cleanup_tables_remaining'              => 0,
			'worker_processes_remaining'            => 0,
			'family_terminal'                       => false,
			'grant_terminal'                        => false,
			'unrelated_state_unchanged'             => false,
			'sibling_domain_unchanged'              => false,
			'raw_wpdb_replayed_outside_transaction' => false,
			'owned_connection_fail_closed'          => false,
			'constraints_enforced'                  => false,
			'autocommit_initial'                    => false,
			'read_write'                            => false,
			'proxied'                               => false,
			'replicated'                            => false,
			'galera'                                => false,
			'error_number'                          => null,
			'sqlstate_class'                        => null,
			'outcomes'                              => array(),
			'status'                                => HarnessContract::OUTCOME_FAILED,
			'passed'                                => false,
		);
	}

	/**
	 * Validates exact output schema and secret-safety constraints.
	 *
	 * @param array<string, mixed> $result Candidate result.
	 */
	public static function validate( array $result ): bool {
		$expectedKeys = array_keys(
			self::base(
				self::validationLane(),
				HarnessContract::CASE_PREFLIGHT,
				HarnessContract::DEFAULT_WORKERS,
				1
			)
		);
		$actualKeys   = array_keys( $result );
		sort( $expectedKeys );
		sort( $actualKeys );

		if ( $expectedKeys !== $actualKeys ) {
			return false;
		}

		if (
			HarnessContract::PROTOCOL_VERSION !== $result['schema_version']
			|| self::RECORD_TYPE !== $result['record_type']
			|| ! in_array( $result['case_id'], array_merge( HarnessContract::cases(), array( HarnessContract::CASE_CLEANUP ) ), true )
			|| ! in_array( $result['database_family'], array( 'mysql', 'mariadb' ), true )
			|| ! is_string( $result['database_version'] )
			|| ! is_string( $result['database_image_digest'] )
			|| ! preg_match( '/^sha256:[a-f0-9]{64}$/D', $result['database_image_digest'] )
			|| ! is_string( $result['artifact_sha256'] )
			|| ! preg_match( '/^[a-f0-9]{64}$/D', $result['artifact_sha256'] )
			|| 'InnoDB' !== $result['engine']
			|| ! in_array( $result['isolation'], array( 'REPEATABLE READ', 'READ COMMITTED' ), true )
			|| ( ! is_bool( $result['mariadb_snapshot_isolation'] ) && null !== $result['mariadb_snapshot_isolation'] )
			|| ! is_string( $result['sql_mode'] )
			|| 1024 < strlen( $result['sql_mode'] )
			|| ( '' !== $result['sql_mode'] && ! preg_match( '/^[A-Z0-9_,]+$/D', $result['sql_mode'] ) )
			|| HarnessContract::WORDPRESS_VERSION !== $result['wordpress_version']
			|| ! is_string( $result['php_version'] )
			|| ! in_array( $result['status'], array( HarnessContract::OUTCOME_PASSED, HarnessContract::OUTCOME_FAILED ), true )
		) {
			return false;
		}

		foreach ( self::COUNT_FIELDS as $field ) {
			if ( ! is_int( $result[ $field ] ) || 0 > $result[ $field ] ) {
				return false;
			}
		}

		foreach ( self::BOOLEAN_FIELDS as $field ) {
			if ( ! is_bool( $result[ $field ] ) ) {
				return false;
			}
		}

		if ( ! is_int( $result['error_number'] ) && null !== $result['error_number'] ) {
			return false;
		}

		if (
			( ! is_string( $result['sqlstate_class'] ) && null !== $result['sqlstate_class'] )
			|| ( is_string( $result['sqlstate_class'] ) && ! preg_match( '/^[A-Z0-9]{2}$/D', $result['sqlstate_class'] ) )
		) {
			return false;
		}

		if ( ! is_array( $result['outcomes'] ) || ! array_is_list( $result['outcomes'] ) ) {
			return false;
		}

		foreach ( $result['outcomes'] as $outcome ) {
			if ( ! is_string( $outcome ) || ! in_array( $outcome, HarnessContract::outcomes(), true ) ) {
				return false;
			}
		}

		return self::containsOnlySafeValues( $result );
	}

	/**
	 * Encodes a validated result or an opaque fixed failure record.
	 *
	 * @param array<string, mixed> $result Candidate result.
	 */
	public static function encode( array $result ): string {
		$record = self::validate( $result ) ? $result : self::opaqueFailure();

		try {
			// phpcs:ignore WordPress.WP.AlternativeFunctions.json_encode_json_encode -- WordPress is intentionally absent from this standalone output boundary.
			return json_encode( $record, JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES );
		} catch ( JsonException ) {
			return '{"schema_version":1,"record_type":"harness_failure","status":"failed","passed":false}';
		}
	}

	/**
	 * Fixed failure output with no copied input or exception detail.
	 *
	 * @return array{schema_version: int, record_type: string, status: string, passed: bool}
	 */
	public static function opaqueFailure(): array {
		return array(
			'schema_version' => HarnessContract::PROTOCOL_VERSION,
			'record_type'    => 'harness_failure',
			'status'         => HarnessContract::OUTCOME_FAILED,
			'passed'         => false,
		);
	}

	/**
	 * Recursively rejects forbidden keys and secret-like strings.
	 *
	 * @param mixed  $value Current value.
	 * @param string $key   Current key.
	 */
	private static function containsOnlySafeValues( mixed $value, string $key = '' ): bool {
		if ( in_array( strtolower( $key ), self::FORBIDDEN_KEYS, true ) ) {
			return false;
		}

		if ( is_array( $value ) ) {
			foreach ( $value as $childKey => $childValue ) {
				if ( ! self::containsOnlySafeValues( $childValue, is_string( $childKey ) ? $childKey : '' ) ) {
					return false;
				}
			}

			return true;
		}

		if ( ! is_string( $value ) ) {
			return true;
		}

		foreach ( self::FORBIDDEN_MARKERS as $marker ) {
			if ( str_contains( $value, $marker ) ) {
				return false;
			}
		}

		if ( preg_match( '/charter-p1-[a-z0-9_-]*material/i', $value ) ) {
			return false;
		}

		if ( 'database_image_digest' !== $key && 'artifact_sha256' !== $key ) {
			if ( preg_match( '/(?<![a-f0-9])[a-f0-9]{64,}(?![a-f0-9])/i', $value ) ) {
				return false;
			}

			if ( preg_match( '/(?<![A-Za-z0-9+\/])[A-Za-z0-9+\/]{80,}={0,2}(?![A-Za-z0-9+\/])/', $value ) ) {
				return false;
			}
		}

		return true;
	}

	/**
	 * Non-secret synthetic lane used only to derive the schema.
	 */
	private static function validationLane(): LaneConfiguration {
		return new LaneConfiguration(
			'fixture',
			3306,
			'fixture',
			'fixture',
			'fixture',
			'mysql',
			'8.0.46',
			'sha256:' . str_repeat( 'a', 64 ),
			'REPEATABLE READ',
			null,
			str_repeat( 'b', 64 )
		);
	}
}
