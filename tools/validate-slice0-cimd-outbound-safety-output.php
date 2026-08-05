<?php
/**
 * Validates and canonicalizes disposable Slice 0 P3 fixed-schema evidence.
 *
 * @package GalatanOvidiu\Charter
 */

declare(strict_types=1);

// Fixed-schema arrays are grouped by contract rather than visual key width.
// phpcs:disable WordPress.Arrays.MultipleStatementAlignment
// phpcs:disable Generic.Formatting.MultipleStatementAlignment

const CHARTER_P3_MAX_RECORD_BYTES = 8192;
const CHARTER_P3_MAX_RECORDS      = 512;

/**
 * Exits through the one bounded validator failure.
 */
function charter_p3_output_fail(): never {
	// phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_fwrite -- Standalone fixed failure boundary.
	fwrite( STDERR, "P3 output validation failed: fixed schema rejected.\n" );
	exit( 1 );
}

/**
 * Returns the exact ordered schema keys.
 *
 * @return list<string>
 */
function charter_p3_output_keys(): array {
	return array(
		'status',
		'phase',
		'case_id',
		'runtime_classification',
		'url_classification',
		'dns_classification',
		'address_classification',
		'media_classification',
		'cache_classification',
		'error_classification',
		'status_code',
		'body_bytes',
		'elapsed_ms',
		'counters',
		'flags',
		'document_fingerprint',
		'redirect_fingerprint',
		'cleanup',
	);
}

/**
 * Checks an exact enum field.
 *
 * @param mixed $value   Candidate value.
 * @param array $allowed Allowed values.
 */
function charter_p3_output_enum( mixed $value, array $allowed ): bool {
	return is_string( $value ) && in_array( $value, $allowed, true );
}

/**
 * Checks one bounded integer.
 *
 * @param mixed $value   Candidate value.
 * @param int   $maximum Inclusive maximum.
 */
function charter_p3_output_integer( mixed $value, int $maximum ): bool {
	return is_int( $value ) && $value >= 0 && $value <= $maximum;
}

/**
 * Checks an exact object key set.
 *
 * @param array<mixed> $value Candidate object.
 * @param array        $keys  Exact keys.
 */
function charter_p3_output_exact_keys( array $value, array $keys ): bool {
	$actual = array_keys( $value );
	sort( $actual );
	sort( $keys );

	return $actual === $keys;
}

/**
 * Rejects secret-shaped material before decoding or forwarding a record.
 *
 * @param string $line Bounded encoded record.
 */
function charter_p3_output_secret_safe( string $line ): bool {
	$patterns = array(
		'/-----BEGIN [A-Z ]*PRIVATE KEY-----/',
		'/\b(?:authorization|proxy-authorization|cookie|set-cookie)\b\s*[:=]/i',
		'/\b(?:Bearer|Basic)\s+[A-Za-z0-9._~+\/-]+=*/i',
		'/["\x27](?:access_token|refresh_token|client_secret|authorization_code|password)["\x27]\s*[:=]/i',
		'/\b(?:HTTP_PROXY|HTTPS_PROXY|ALL_PROXY|NO_PROXY|DATABASE_URL)\s*=/i',
		'#https?://[^\s/@:]+:[^\s/@]+@#i',
	);

	foreach ( $patterns as $pattern ) {
		if ( 1 === preg_match( $pattern, $line ) ) {
			return false;
		}
	}

	return true;
}

/**
 * Validates and orders one decoded record.
 *
 * @param mixed $decoded Candidate decoded value.
 * @return array<string, mixed> Canonical record.
 */
function charter_p3_output_record( mixed $decoded ): array {
	if ( ! is_array( $decoded ) || ! charter_p3_output_exact_keys( $decoded, charter_p3_output_keys() ) ) {
		charter_p3_output_fail();
	}

	$enums = array(
		'status'                 => array( 'passed', 'failed' ),
		'phase'                  => array( 'preflight', 'pure', 'retained', 'hostile', 'proxy', 'timeout', 'limit', 'interruption', 'cleanup', 'summary' ),
		'runtime_classification' => array( 'static', 'pure-php', 'wordpress-p2', 'wordpress-php84-direct', 'wordpress-php84-reused', 'wordpress-php85-direct', 'wordpress-php85-reused', 'interruption', 'cleanup', 'summary' ),
		'url_classification'     => array( 'not-applicable', 'accepted', 'rejected' ),
		'dns_classification'     => array(
			'not-applicable',
			'safe',
			'special',
			'mixed',
			'rebind',
			'failure',
			'timeout',
			'bounded',
			'resolved',
			'no-answer',
			'nxdomain',
			'servfail',
			'malformed',
			'truncated',
			'cname-loop',
			'cname-depth',
			'address-limit',
			'record-limit',
			'message-limit',
			'message-bytes',
			'aggregate-bytes',
			'deadline',
			'unsafe-address',
			'no_answer',
			'cname_loop',
			'cname_depth',
			'address_limit',
			'record_limit',
			'message_limit',
			'message_bytes',
			'aggregate_bytes',
			'unsafe_address',
		),
		'address_classification' => array( 'not-applicable', 'screened', 'special', 'mismatch', 'unavailable' ),
		'media_classification'   => array( 'not-applicable', 'accepted-json', 'rejected' ),
		'cache_classification'   => array( 'not-applicable', 'fresh', 'stale', 'no-cache', 'no-store', 'fallback' ),
		'error_classification'   => array( 'none', 'capability-unavailable', 'fixture-unavailable', 'test-failed', 'expected-rejection', 'interrupted', 'cleanup-incomplete', 'schema-rejected' ),
	);

	foreach ( $enums as $field => $allowed ) {
		if ( ! charter_p3_output_enum( $decoded[ $field ], $allowed ) ) {
			charter_p3_output_fail();
		}
	}

	if ( ! is_string( $decoded['case_id'] ) || 1 !== preg_match( '/^[a-z0-9][a-z0-9-]{0,63}$/D', $decoded['case_id'] ) ) {
		charter_p3_output_fail();
	}

	if (
		! charter_p3_output_integer( $decoded['status_code'], 599 )
		|| ! charter_p3_output_integer( $decoded['body_bytes'], 65536 )
		|| ! charter_p3_output_integer( $decoded['elapsed_ms'], 300000 )
	) {
		charter_p3_output_fail();
	}

	$counterKeys = array( 'dns_query', 'tcp_connection', 'tls_handshake', 'http_request', 'redirect_target', 'embedded_url', 'proxy', 'credential_path' );
	$flagKeys    = array( 'tls_hostname_verified', 'screened_peer_matched', 'redirect_followed', 'snapshot_authoritative', 'stale_fallback_used', 'consent_reusable', 'credential_disturbed' );
	$cleanupKeys = array( 'processes_remaining', 'containers_remaining', 'networks_remaining', 'temp_files_remaining', 'private_keys_remaining', 'hooks_remaining', 'listeners_remaining' );

	if (
		! is_array( $decoded['counters'] )
		|| ! charter_p3_output_exact_keys( $decoded['counters'], $counterKeys )
		|| ! is_array( $decoded['flags'] )
		|| ! charter_p3_output_exact_keys( $decoded['flags'], $flagKeys )
		|| ! is_array( $decoded['cleanup'] )
		|| ! charter_p3_output_exact_keys( $decoded['cleanup'], $cleanupKeys )
	) {
		charter_p3_output_fail();
	}

	foreach ( $counterKeys as $key ) {
		if ( ! charter_p3_output_integer( $decoded['counters'][ $key ], 1000000 ) ) {
			charter_p3_output_fail();
		}
	}

	foreach ( $flagKeys as $key ) {
		if ( ! is_bool( $decoded['flags'][ $key ] ) ) {
			charter_p3_output_fail();
		}
	}

	foreach ( $cleanupKeys as $key ) {
		if ( ! charter_p3_output_integer( $decoded['cleanup'][ $key ], 1000 ) ) {
			charter_p3_output_fail();
		}
	}

	foreach ( array( 'document_fingerprint', 'redirect_fingerprint' ) as $field ) {
		if ( ! is_string( $decoded[ $field ] ) || ( 'none' !== $decoded[ $field ] && 1 !== preg_match( '/^[a-f0-9]{64}$/D', $decoded[ $field ] ) ) ) {
			charter_p3_output_fail();
		}
	}

	$canonical = array();
	foreach ( charter_p3_output_keys() as $key ) {
		$canonical[ $key ] = $decoded[ $key ];
	}

	return $canonical;
}

/**
 * Emits one already validated record.
 *
 * @param array<string, mixed> $record Canonical fixed record.
 */
function charter_p3_output_emit( array $record ): void {
	// phpcs:ignore WordPress.WP.AlternativeFunctions.json_encode_json_encode -- WordPress is intentionally absent from this standalone boundary.
	$encoded = json_encode( $record, JSON_UNESCAPED_SLASHES );
	if ( ! is_string( $encoded ) || strlen( $encoded ) > CHARTER_P3_MAX_RECORD_BYTES || ! charter_p3_output_secret_safe( $encoded ) ) {
		charter_p3_output_fail();
	}

	// phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_fwrite -- Writes only canonical fixed-schema evidence.
	fwrite( STDOUT, $encoded . PHP_EOL );
}

/**
 * Returns a zero-valued fixed evidence record.
 *
 * @return array<string, mixed>
 */
function charter_p3_output_base_record(): array {
	return array(
		'status'                 => 'passed',
		'phase'                  => 'preflight',
		'case_id'                => 'compose-static',
		'runtime_classification' => 'static',
		'url_classification'     => 'not-applicable',
		'dns_classification'     => 'not-applicable',
		'address_classification' => 'not-applicable',
		'media_classification'   => 'not-applicable',
		'cache_classification'   => 'not-applicable',
		'error_classification'   => 'none',
		'status_code'            => 0,
		'body_bytes'             => 0,
		'elapsed_ms'             => 0,
		'counters'               => array(
			'dns_query'       => 0,
			'tcp_connection'  => 0,
			'tls_handshake'    => 0,
			'http_request'     => 0,
			'redirect_target'  => 0,
			'embedded_url'     => 0,
			'proxy'            => 0,
			'credential_path'  => 0,
		),
		'flags'                  => array(
			'tls_hostname_verified'  => false,
			'screened_peer_matched'   => false,
			'redirect_followed'        => false,
			'snapshot_authoritative'  => false,
			'stale_fallback_used'      => false,
			'consent_reusable'         => false,
			'credential_disturbed'     => false,
		),
		'document_fingerprint'   => 'none',
		'redirect_fingerprint'   => 'none',
		'cleanup'                => array(
			'processes_remaining'  => 0,
			'containers_remaining' => 0,
			'networks_remaining'   => 0,
			'temp_files_remaining' => 0,
			'private_keys_remaining' => 0,
			'hooks_remaining'      => 0,
			'listeners_remaining'  => 0,
		),
	);
}

/**
 * Extracts fixed container targets from Compose short or expanded volumes.
 *
 * @param array<string, mixed> $service Decoded Compose service.
 * @return list<string> Container volume targets.
 */
function charter_p3_output_volume_targets( array $service ): array {
	$volumes = $service['volumes'] ?? null;
	if ( ! is_array( $volumes ) ) {
		return array();
	}

	$known   = array( '/certs/ca.crt', '/certs/ca.key', '/certs/server.crt', '/certs/server.key' );
	$targets = array();
	foreach ( $volumes as $volume ) {
		if ( is_array( $volume ) && is_string( $volume['target'] ?? null ) ) {
			$targets[] = $volume['target'];
			continue;
		}

		if ( ! is_string( $volume ) ) {
			continue;
		}

		foreach ( $known as $target ) {
			if ( str_contains( $volume, ':' . $target ) ) {
				$targets[] = $target;
			}
		}
	}

	return array_values( array_unique( $targets ) );
}

/**
 * Validates the private Docker Compose JSON projection without forwarding it.
 *
 * @param string $path Private Compose JSON path.
 */
function charter_p3_output_validate_compose( string $path ): void {
	// phpcs:ignore WordPress.WP.AlternativeFunctions.file_get_contents_file_get_contents -- Reads one private bounded local config projection.
	$raw = file_get_contents( $path );
	if ( ! is_string( $raw ) || strlen( $raw ) > 1048576 || ! charter_p3_output_secret_safe( $raw ) ) {
		charter_p3_output_fail();
	}

	$compose = json_decode( $raw, true );
	if ( ! is_array( $compose ) || ! is_array( $compose['services'] ?? null ) || ! is_array( $compose['networks'] ?? null ) ) {
		charter_p3_output_fail();
	}

	$expectedServices = array( 'control', 'dns', 'embedded-url-sink', 'http-proxy', 'origin', 'origin6', 'redirect-sink', 'socks-proxy', 'special-sink', 'wp84', 'wp85' );
	$services         = array_keys( $compose['services'] );
	sort( $services );
	if ( $services !== $expectedServices ) {
		charter_p3_output_fail();
	}

	foreach ( $compose['services'] as $serviceName => $service ) {
		$securityOptions = is_array( $service['security_opt'] ?? null ) ? $service['security_opt'] : array();
		if (
			! is_array( $service )
			|| ! is_string( $service['image'] ?? null )
			|| 1 !== preg_match( '/@sha256:[a-f0-9]{64}$/D', $service['image'] )
			|| isset( $service['build'] )
			|| isset( $service['ports'] )
			|| isset( $service['network_mode'] )
			|| isset( $service['extra_hosts'] )
			|| true !== ( $service['read_only'] ?? null )
			|| array( 'hostile' ) !== array_keys( $service['networks'] ?? array() )
			|| ! in_array( 'ALL', $service['cap_drop'] ?? array(), true )
			|| ( ! in_array( 'no-new-privileges:true', $securityOptions, true ) && ! in_array( 'no-new-privileges=true', $securityOptions, true ) )
		) {
			charter_p3_output_fail();
		}

		$targets            = charter_p3_output_volume_targets( $service );
		$tlsServerConsumers = array( 'origin', 'origin6', 'redirect-sink', 'embedded-url-sink', 'special-sink' );
		$caConsumers        = array( 'http-proxy', 'socks-proxy', 'wp84', 'wp85' );
		$expectsServer      = in_array( $serviceName, $tlsServerConsumers, true );
		$expectsCa          = in_array( $serviceName, $caConsumers, true );
		// phpcs:disable WordPress.PHP.YodaConditions.NotYoda -- Both sides are runtime booleans.
		if ( isset( $service['volumes'] ) && (
			$expectsServer !== in_array( '/certs/server.crt', $targets, true )
			|| $expectsServer !== in_array( '/certs/server.key', $targets, true )
			|| $expectsCa !== in_array( '/certs/ca.crt', $targets, true )
			|| in_array( '/certs/ca.key', $targets, true )
		) ) {
			charter_p3_output_fail();
		}
		// phpcs:enable WordPress.PHP.YodaConditions.NotYoda
	}

	if (
		array( 'hostile' ) !== array_keys( $compose['networks'] )
		|| true !== ( $compose['networks']['hostile']['internal'] ?? null )
		|| true !== ( $compose['networks']['hostile']['enable_ipv6'] ?? null )
		|| true === ( $compose['networks']['hostile']['external'] ?? false )
	) {
		charter_p3_output_fail();
	}

	charter_p3_output_emit( charter_p3_output_record( charter_p3_output_base_record() ) );
}

/**
 * Validates one private fixture-control counter capture and emits aggregates.
 *
 * @param string $path    Private counter capture path.
 * @param string $phase   Fixed evidence phase.
 * @param string $caseId  Fixed case identifier.
 * @param string $runtime Fixed runtime classification.
 */
function charter_p3_output_validate_counters( string $path, string $phase, string $caseId, string $runtime ): void {
	// phpcs:ignore WordPress.WP.AlternativeFunctions.file_get_contents_file_get_contents -- Reads one private bounded local counter capture.
	$raw = file_get_contents( $path );
	if ( ! is_string( $raw ) || strlen( $raw ) > CHARTER_P3_MAX_RECORD_BYTES || ! charter_p3_output_secret_safe( $raw ) ) {
		charter_p3_output_fail();
	}

	$decoded     = json_decode( $raw, true );
	$counterKeys = array(
		'dns_query',
		'dns_client_a',
		'dns_client_aaaa',
		'tcp_connection',
		'tls_handshake',
		'http_request',
		'origin_tcp_connection',
		'origin_tls_handshake',
		'origin_http_request',
		'redirect_target',
		'embedded_url',
		'special_tcp_connection',
		'special_tls_handshake',
		'special_http_request',
		'proxy',
		'http_proxy_connection',
		'socks_proxy_connection',
		'credential_path',
		'sensitive_egress',
	);

	if (
		! is_array( $decoded )
		|| ! charter_p3_output_exact_keys( $decoded, array( 'status', 'scenario', 'counters' ) )
		|| 'ready' !== ( $decoded['status'] ?? null )
		|| ! is_string( $decoded['scenario'] ?? null )
		|| 1 !== preg_match( '/^[a-z0-9][a-z0-9-]{0,63}$/D', $decoded['scenario'] )
		|| ! is_array( $decoded['counters'] ?? null )
		|| ! charter_p3_output_exact_keys( $decoded['counters'], $counterKeys )
	) {
		charter_p3_output_fail();
	}

	foreach ( $counterKeys as $key ) {
		if ( ! charter_p3_output_integer( $decoded['counters'][ $key ], 1000000 ) ) {
			charter_p3_output_fail();
		}
	}

	$record                           = charter_p3_output_base_record();
	$record['phase']                  = $phase;
	$record['case_id']                = $caseId;
	$record['runtime_classification'] = $runtime;
	$record['dns_classification']     = $decoded['counters']['dns_query'] > 0 ? 'bounded' : 'not-applicable';
	$record['address_classification'] = $decoded['counters']['tcp_connection'] > 0 ? 'screened' : 'not-applicable';
	$record['counters']               = array(
		'dns_query'       => $decoded['counters']['dns_query'],
		'tcp_connection'  => $decoded['counters']['tcp_connection'],
		'tls_handshake'    => $decoded['counters']['tls_handshake'],
		'http_request'     => $decoded['counters']['http_request'],
		'redirect_target'  => $decoded['counters']['redirect_target'],
		'embedded_url'     => $decoded['counters']['embedded_url'],
		'proxy'            => $decoded['counters']['proxy'],
		'credential_path'  => $decoded['counters']['credential_path'],
	);

	$unsafeEgress = $decoded['counters']['sensitive_egress'] > 0;
	if ( $unsafeEgress ) {
		$record['status']               = 'failed';
		$record['error_classification'] = 'schema-rejected';
	}

	charter_p3_output_emit( charter_p3_output_record( $record ) );
	if ( $unsafeEgress ) {
		exit( 1 );
	}
}

/**
 * Runs the standalone validator.
 */
function charter_p3_output_main(): void {
	global $argv;

	if ( 3 === count( $argv ) && '--compose-config' === $argv[1] ) {
		charter_p3_output_validate_compose( $argv[2] );
		return;
	}

	if ( 6 === count( $argv ) && '--counter-capture' === $argv[1] ) {
		charter_p3_output_validate_counters( $argv[2], $argv[3], $argv[4], $argv[5] );
		return;
	}

	if ( 1 !== count( $argv ) ) {
		charter_p3_output_fail();
	}

	$count = 0;
	$line  = fgets( STDIN, CHARTER_P3_MAX_RECORD_BYTES + 2 );
	while ( false !== $line ) {
		++$count;
		if ( $count > CHARTER_P3_MAX_RECORDS || strlen( $line ) > CHARTER_P3_MAX_RECORD_BYTES || ! str_ends_with( $line, "\n" ) || ! charter_p3_output_secret_safe( $line ) ) {
			charter_p3_output_fail();
		}

		try {
			$decoded = json_decode( $line, true, 32, JSON_THROW_ON_ERROR );
		} catch ( JsonException ) {
			charter_p3_output_fail();
		}

		charter_p3_output_emit( charter_p3_output_record( $decoded ) );
		$line = fgets( STDIN, CHARTER_P3_MAX_RECORD_BYTES + 2 );
	}

	if ( 0 === $count ) {
		charter_p3_output_fail();
	}
}

charter_p3_output_main();
