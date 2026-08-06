<?php
/**
 * Exercises the hostile fixture protocols without emitting private captures.
 *
 * @package GalatanOvidiu\Charter
 */

declare(strict_types=1);

// Standalone disposable probe: WordPress is intentionally not bootstrapped.
// phpcs:disable WordPress.PHP.NoSilencedErrors.Discouraged
// phpcs:disable WordPress.WP.AlternativeFunctions
// phpcs:disable WordPress.Arrays.MultipleStatementAlignment

/**
 * Stops with one fixed exit code and no captured material.
 */
function charter_p3_probe_fail(): never {
	exit( 1 );
}

/**
 * Calls the body-free fixed fixture control protocol.
 *
 * @param string $path   Fixed control path.
 * @param string $method GET or POST.
 * @return array<string, mixed>
 */
function charter_p3_probe_control( string $path, string $method = 'GET' ): array {
	$base = getenv( 'P3_FIXTURE_CONTROL_URL' );
	if ( ! is_string( $base ) || '' === $base || 1 !== preg_match( '#^/[a-z0-9/-]+$#D', $path ) ) {
		charter_p3_probe_fail();
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
		charter_p3_probe_fail();
	}

	return $data;
}

/**
 * Resets one fixed scenario.
 *
 * @param string $scenario Fixed scenario name.
 */
function charter_p3_probe_reset( string $scenario ): void {
	$result = charter_p3_probe_control( '/scenario/' . $scenario, 'POST' );
	// phpcs:ignore WordPress.PHP.YodaConditions.NotYoda -- Both sides are runtime values.
	if ( $scenario !== ( $result['scenario'] ?? null ) ) {
		charter_p3_probe_fail();
	}
}

/**
 * Returns current fixed counters.
 *
 * @return array<string, int>
 */
function charter_p3_probe_counters(): array {
	$result   = charter_p3_probe_control( '/counters' );
	$counters = $result['counters'] ?? null;
	if ( ! is_array( $counters ) ) {
		charter_p3_probe_fail();
	}

	foreach ( $counters as $value ) {
		if ( ! is_int( $value ) || $value < 0 ) {
			charter_p3_probe_fail();
		}
	}

	return $counters;
}

/**
 * Asserts exact selected counter values.
 *
 * @param array<string, int> $expected Exact selected values.
 */
function charter_p3_probe_expect_counters( array $expected ): void {
	$counters = charter_p3_probe_counters();
	foreach ( $expected as $name => $value ) {
		// phpcs:ignore WordPress.PHP.YodaConditions.NotYoda -- Both sides are runtime values.
		if ( $value !== ( $counters[ $name ] ?? null ) ) {
			charter_p3_probe_fail();
		}
	}
}

/**
 * Runs one direct pinned TLS request and returns bounded observations.
 *
 * @param int    $bodyLimit Inclusive body byte limit.
 * @param string $peerIp    Exact proof-owned peer.
 * @return array{ok: bool, status: int, body_bytes: int, primary_ip: string}
 */
function charter_p3_probe_direct( int $bodyLimit = 5120, string $peerIp = '198.17.0.34' ): array {
	$url    = getenv( 'P3_FIXTURE_CLIENT_ID' );
	$caFile = getenv( 'P3_FIXTURE_CA_FILE' );
	if ( ! is_string( $url ) || ! is_string( $caFile ) || ! is_file( $caFile ) || ! function_exists( 'curl_init' ) ) {
		charter_p3_probe_fail();
	}

	$bodyBytes = 0;
	$handle    = curl_init( $url );
	if ( false === $handle ) {
		charter_p3_probe_fail();
	}

	$options = array(
		CURLOPT_CUSTOMREQUEST     => 'GET',
		CURLOPT_HTTPHEADER        => array( 'Accept: application/json', 'Accept-Encoding: identity', 'Cache-Control: no-cache', 'User-Agent: Charter-P3-Probe/1' ),
		CURLOPT_CONNECTTIMEOUT    => 3,
		CURLOPT_TIMEOUT           => 5,
		CURLOPT_FOLLOWLOCATION    => false,
		CURLOPT_MAXREDIRS         => 0,
		CURLOPT_SSL_VERIFYPEER    => true,
		CURLOPT_SSL_VERIFYHOST    => 2,
		CURLOPT_CAINFO            => $caFile,
		CURLOPT_PROXY             => '',
		CURLOPT_NOPROXY           => '*',
		CURLOPT_RESOLVE           => array( 'client.charter.test:443:' . $peerIp ),
		CURLOPT_FRESH_CONNECT     => true,
		CURLOPT_FORBID_REUSE      => true,
		CURLOPT_ENCODING          => null,
		CURLOPT_PREREQFUNCTION    => static function ( CurlHandle $unused, string $primaryIp, string $localIp, int $primaryPort, int $localPort ) use ( $peerIp ): int {
			unset( $unused, $localIp, $localPort );
			return $peerIp === $primaryIp && 443 === $primaryPort ? CURL_PREREQFUNC_OK : CURL_PREREQFUNC_ABORT;
		},
		CURLOPT_HEADERFUNCTION    => static function ( CurlHandle $unused, string $line ): int {
			unset( $unused );
			return strlen( $line ) <= 8192 ? strlen( $line ) : 0;
		},
		CURLOPT_WRITEFUNCTION     => static function ( CurlHandle $unused, string $chunk ) use ( &$bodyBytes, $bodyLimit ): int {
			unset( $unused );
			$length = strlen( $chunk );
			if ( $bodyBytes + $length > $bodyLimit ) {
				return 0;
			}
			$bodyBytes += $length;
			return $length;
		},
	);

	if ( ! curl_setopt_array( $handle, $options ) ) {
		unset( $handle );
		charter_p3_probe_fail();
	}

	$ok        = curl_exec( $handle );
	$status    = (int) curl_getinfo( $handle, CURLINFO_RESPONSE_CODE );
	$primaryIp = (string) curl_getinfo( $handle, CURLINFO_PRIMARY_IP );
	unset( $handle );

	return array(
		'ok'         => false !== $ok,
		'status'     => $status,
		'body_bytes' => $bodyBytes,
		'primary_ip' => $primaryIp,
	);
}

/**
 * Encodes one DNS qname.
 *
 * @param string $name DNS qname.
 * @return string Encoded wire name.
 */
function charter_p3_probe_dns_name( string $name ): string {
	$wire = '';
	foreach ( explode( '.', $name ) as $label ) {
		$wire .= chr( strlen( $label ) ) . $label;
	}

	return $wire . "\0";
}

/**
 * Sends one bounded A query to the explicit fixture DNS server.
 */
function charter_p3_probe_dns_query(): string {
	$server = getenv( 'P3_FIXTURE_DNS_SERVER' );
	if ( ! is_string( $server ) || 1 !== preg_match( '/^[0-9.]+:[0-9]+$/D', $server ) ) {
		charter_p3_probe_fail();
	}

	$socket = @stream_socket_client( 'udp://' . $server, $number, $message, 1 );
	unset( $number, $message );
	if ( false === $socket ) {
		charter_p3_probe_fail();
	}

	stream_set_timeout( $socket, 1 );
	$query = pack( 'nnnnnn', 1, 0x0100, 1, 0, 0, 0 ) . charter_p3_probe_dns_name( 'client.charter.test' ) . pack( 'nn', 1, 1 );
	if ( strlen( $query ) !== @fwrite( $socket, $query ) ) {
		fclose( $socket );
		charter_p3_probe_fail();
	}
	$response = @fread( $socket, 16384 );
	fclose( $socket );

	return is_string( $response ) ? $response : '';
}

/**
 * Contacts one exact expected-red proxy observation sink.
 *
 * @param string $protocol Fixed proxy protocol.
 */
function charter_p3_probe_proxy( string $protocol ): void {
	$target = in_array( $protocol, array( 'http', 'connect' ), true ) ? getenv( 'P3_FIXTURE_PROXY_URL' ) : 'tcp://198.17.0.41:1080';
	if ( ! is_string( $target ) || '' === $target ) {
		charter_p3_probe_fail();
	}

	if ( str_starts_with( $target, 'http://' ) ) {
		$target = 'tcp://' . substr( $target, strlen( 'http://' ) );
	}
	$socket = @stream_socket_client( $target, $number, $message, 2 );
	unset( $number, $message );
	if ( false === $socket ) {
		charter_p3_probe_fail();
	}
	stream_set_timeout( $socket, 1 );
	if ( 'http' === $protocol ) {
		@fwrite( $socket, "GET https://client.charter.test/client.json HTTP/1.1\r\nHost: client.charter.test\r\n\r\n" );
		@fread( $socket, 128 );
	} elseif ( 'connect' === $protocol ) {
		@fwrite( $socket, "CONNECT client.charter.test:443 HTTP/1.1\r\nHost: client.charter.test:443\r\n\r\n" );
		@fread( $socket, 128 );
	} else {
		@fwrite( $socket, "\x05\x01\x00" );
		if ( "\x05\x00" !== @fread( $socket, 2 ) ) {
			fclose( $socket );
			charter_p3_probe_fail();
		}
		$request = 'socks-local' === $protocol
			? "\x05\x01\x00\x01" . inet_pton( '198.18.0.10' ) . pack( 'n', 443 )
			: "\x05\x01\x00\x03" . chr( strlen( 'client.charter.test' ) ) . 'client.charter.test' . pack( 'n', 443 );
		@fwrite( $socket, $request );
		@fread( $socket, 10 );
	}
	fclose( $socket );
}

/**
 * Runs one exact fixture-control lane.
 */
function charter_p3_probe_main(): void {
	global $argv;
	$mode = (string) ( $argv[1] ?? '' );

	if ( 'direct' === $mode ) {
		charter_p3_probe_reset( 'safe' );
		$result = charter_p3_probe_direct();
		if ( ! $result['ok'] || 200 !== $result['status'] || '198.17.0.34' !== $result['primary_ip'] || $result['body_bytes'] > 5120 ) {
			charter_p3_probe_fail();
		}
		charter_p3_probe_expect_counters(
			array(
				'origin_http_request'  => 1,
				'special_http_request' => 0,
				'redirect_target'      => 0,
				'proxy'                => 0,
				'sensitive_egress'     => 0,
			)
		);
		return;
	}

	if ( 'redirect' === $mode ) {
		charter_p3_probe_reset( 'redirect-public' );
		$result = charter_p3_probe_direct();
		if ( ! $result['ok'] || 302 !== $result['status'] ) {
			charter_p3_probe_fail();
		}
		charter_p3_probe_expect_counters(
			array(
				'origin_http_request' => 1,
				'redirect_target'     => 0,
				'proxy'               => 0,
			)
		);
		return;
	}

	if ( 'timeout' === $mode ) {
		charter_p3_probe_reset( 'first-byte-delay' );
		$result = charter_p3_probe_direct();
		if ( $result['ok'] ) {
			charter_p3_probe_fail();
		}
		charter_p3_probe_expect_counters(
			array(
				'origin_http_request' => 1,
				'redirect_target'     => 0,
				'proxy'               => 0,
			)
		);
		return;
	}

	if ( 'connect-timeout' === $mode ) {
		charter_p3_probe_reset( 'safe' );
		$result = charter_p3_probe_direct( 5120, '198.17.0.250' );
		if ( $result['ok'] ) {
			charter_p3_probe_fail();
		}
		charter_p3_probe_expect_counters(
			array(
				'tcp_connection' => 0,
				'tls_handshake'   => 0,
				'http_request'    => 0,
				'proxy'           => 0,
			)
		);
		return;
	}

	if ( 'tls-timeout' === $mode ) {
		charter_p3_probe_reset( 'tls-delay' );
		$result = charter_p3_probe_direct();
		if ( $result['ok'] ) {
			charter_p3_probe_fail();
		}
		charter_p3_probe_expect_counters(
			array(
				'origin_tcp_connection' => 1,
				'origin_tls_handshake'  => 0,
				'origin_http_request'   => 0,
				'proxy'                 => 0,
			)
		);
		return;
	}

	if ( 'limit' === $mode ) {
		charter_p3_probe_reset( 'body-5121' );
		$result = charter_p3_probe_direct();
		if ( $result['ok'] || $result['body_bytes'] > 5120 ) {
			charter_p3_probe_fail();
		}
		charter_p3_probe_expect_counters(
			array(
				'origin_http_request' => 1,
				'redirect_target'     => 0,
				'proxy'               => 0,
			)
		);
		return;
	}

	if ( 'rebind' === $mode ) {
		charter_p3_probe_reset( 'dns-rebind' );
		$first  = charter_p3_probe_dns_query();
		$second = charter_p3_probe_dns_query();
		if ( ! str_contains( $first, inet_pton( '198.17.0.34' ) ) || ! str_contains( $second, inet_pton( '198.18.0.10' ) ) ) {
			charter_p3_probe_fail();
		}
		$result = charter_p3_probe_direct();
		if ( ! $result['ok'] || '198.17.0.34' !== $result['primary_ip'] ) {
			charter_p3_probe_fail();
		}
		charter_p3_probe_expect_counters(
			array(
				'dns_query'              => 2,
				'origin_http_request'     => 1,
				'special_tcp_connection' => 0,
				'special_http_request'    => 0,
			)
		);
		return;
	}

	if ( 'expected-red-rebind' === $mode ) {
		charter_p3_probe_reset( 'dns-rebind' );
		$first  = charter_p3_probe_dns_query();
		$second = charter_p3_probe_dns_query();
		if ( ! str_contains( $first, inet_pton( '198.17.0.34' ) ) || ! str_contains( $second, inet_pton( '198.18.0.10' ) ) ) {
			charter_p3_probe_fail();
		}
		$result = charter_p3_probe_direct( 5120, '198.18.0.10' );
		if ( ! $result['ok'] || '198.18.0.10' !== $result['primary_ip'] ) {
			charter_p3_probe_fail();
		}
		charter_p3_probe_expect_counters(
			array(
				'dns_query'              => 2,
				'origin_tcp_connection'  => 0,
				'special_tcp_connection' => 1,
				'special_tls_handshake'   => 1,
				'special_http_request'    => 1,
				'proxy'                   => 0,
			)
		);
		return;
	}

	if ( in_array( $mode, array( 'expected-red-proxy-http', 'expected-red-proxy-connect', 'expected-red-proxy-socks-local', 'expected-red-proxy-socks-remote' ), true ) ) {
		charter_p3_probe_reset( 'safe' );
		$protocol = substr( $mode, strlen( 'expected-red-proxy-' ) );
		charter_p3_probe_proxy( $protocol );
		charter_p3_probe_expect_counters(
			array(
				'proxy'                  => 1,
				'origin_tcp_connection'  => 0,
				'special_tcp_connection' => 1,
				'special_tls_handshake'  => 1,
				'special_http_request'    => 1,
				'sensitive_egress'        => 0,
			)
		);
		return;
	}

	charter_p3_probe_fail();
}

charter_p3_probe_main();
