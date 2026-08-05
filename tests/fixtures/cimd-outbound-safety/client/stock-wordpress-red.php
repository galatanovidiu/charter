<?php
/**
 * Executes the uniquely labelled incomplete stock-safe WordPress red lane.
 *
 * @package GalatanOvidiu\Charter
 */

declare(strict_types=1);

// Standalone disposable expected-red control using the exact Core HTTP stack.
// phpcs:disable WordPress.PHP.NoSilencedErrors.Discouraged
// phpcs:disable WordPress.WP.AlternativeFunctions

require dirname( __DIR__ ) . '/bootstrap-wordpress-http.php';

/**
 * Stops without emitting any captured request or response material.
 */
function charter_p3_stock_red_fail(): never {
	exit( 1 );
}

/**
 * Calls one fixed fixture-control endpoint.
 *
 * @param string $path   Fixed control path.
 * @param string $method GET or POST.
 * @return array<string, mixed> Fixed control response.
 */
function charter_p3_stock_red_control( string $path, string $method = 'GET' ): array {
	$base = getenv( 'P3_FIXTURE_CONTROL_URL' );
	if ( ! is_string( $base ) || '' === $base || 1 !== preg_match( '#^/[a-z0-9/-]+$#D', $path ) ) {
		charter_p3_stock_red_fail();
	}

	$context = stream_context_create(
		array(
			'http' => array(
				'method'        => $method,
				'timeout'       => 2,
				'ignore_errors' => true,
				'header'        => "Connection: close\r\n",
			),
		)
	);
	$body    = @file_get_contents( $base . $path, false, $context );
	$data    = is_string( $body ) && strlen( $body ) <= 8192 ? json_decode( $body, true ) : null;

	if ( ! is_array( $data ) || 'ready' !== ( $data['status'] ?? null ) ) {
		charter_p3_stock_red_fail();
	}

	return $data;
}

$charter_p3_stock_red_url = getenv( 'P3_FIXTURE_CLIENT_ID' );
$charter_p3_stock_red_ca  = getenv( 'P3_FIXTURE_CA_FILE' );
if ( ! is_string( $charter_p3_stock_red_url ) || ! is_string( $charter_p3_stock_red_ca ) || ! is_file( $charter_p3_stock_red_ca ) ) {
	charter_p3_stock_red_fail();
}

$charter_p3_stock_red_reset = charter_p3_stock_red_control( '/scenario/dns-rebind', 'POST' );
if ( 'dns-rebind' !== ( $charter_p3_stock_red_reset['scenario'] ?? null ) ) {
	charter_p3_stock_red_fail();
}

$charter_p3_stock_red_response = wp_remote_get(
	$charter_p3_stock_red_url,
	array(
		'timeout'            => 5,
		'redirection'        => 0,
		'reject_unsafe_urls' => true,
		'sslverify'          => true,
		'sslcertificates'    => $charter_p3_stock_red_ca,
		'blocking'           => true,
		'decompress'         => false,
		'cookies'            => array(),
		'body'               => null,
		'user-agent'         => 'Charter-CIMD-Proof/1',
		'headers'            => array(
			'Accept'          => 'application/json',
			'Accept-Encoding' => 'identity',
			'Cache-Control'   => 'no-cache',
		),
	)
);

if ( is_wp_error( $charter_p3_stock_red_response ) || 200 !== wp_remote_retrieve_response_code( $charter_p3_stock_red_response ) ) {
	charter_p3_stock_red_fail();
}

$charter_p3_stock_red_state    = charter_p3_stock_red_control( '/counters' );
$charter_p3_stock_red_counters = $charter_p3_stock_red_state['counters'] ?? null;
if ( ! is_array( $charter_p3_stock_red_counters ) ) {
	charter_p3_stock_red_fail();
}

$charter_p3_stock_red_expected = array(
	'dns_client_a'           => 2,
	'origin_tcp_connection'  => 0,
	'origin_tls_handshake'   => 0,
	'origin_http_request'    => 0,
	'special_tcp_connection' => 1,
	'special_tls_handshake'  => 1,
	'special_http_request'   => 1,
	'redirect_target'        => 0,
	'embedded_url'           => 0,
	'proxy'                  => 0,
	'sensitive_egress'       => 0,
);
foreach ( $charter_p3_stock_red_expected as $charter_p3_stock_red_counter => $charter_p3_stock_red_value ) {
	// phpcs:ignore WordPress.PHP.YodaConditions.NotYoda -- Both sides are fixed runtime integers.
	if ( $charter_p3_stock_red_value !== ( $charter_p3_stock_red_counters[ $charter_p3_stock_red_counter ] ?? null ) ) {
		charter_p3_stock_red_fail();
	}
}
