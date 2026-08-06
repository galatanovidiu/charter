<?php
/**
 * Shared bounded-state primitives for the disposable P3 hostile fixture.
 *
 * This file deliberately never stores request headers, request bodies, DNS
 * packets, certificate material, or environment values. Only fixed scenario
 * names and integer counters cross the fixture control boundary.
 *
 * @package GalatanOvidiu\Charter
 */

declare(strict_types=1);

// Standalone disposable fixture: WordPress is intentionally not bootstrapped.
// phpcs:disable Squiz.Commenting.FunctionCommentThrowTag.Missing
// phpcs:disable WordPress.PHP.NoSilencedErrors.Discouraged
// phpcs:disable WordPress.Security.EscapeOutput.OutputNotEscaped
// phpcs:disable WordPress.WP.AlternativeFunctions

const CHARTER_P3_COUNTERS = array(
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

const CHARTER_P3_SCENARIOS = array(
	'safe',
	'embedded-urls',
	'dns-nxdomain',
	'dns-servfail',
	'dns-timeout',
	'dns-aaaa-timeout',
	'dns-staggered-timeout',
	'dns-malformed',
	'dns-truncated',
	'dns-cname-loop',
	'dns-cname-safe',
	'dns-cname-special',
	'dns-mixed',
	'dns-rebind',
	'dns-sibling',
	'dns-safe-reorder',
	'dns-trailing-data',
	'dns-sections-64',
	'dns-sections-65',
	'tls-delay',
	'first-byte-delay',
	'slow-body',
	'early-close',
	'valid-json-prefix-truncated',
	'redirect-public',
	'redirect-loopback',
	'redirect-private',
	'redirect-special',
	'redirect-http',
	'redirect-port',
	'redirect-credentials',
	'redirect-malformed',
	'redirect-long',
	'status-199',
	'status-204',
	'status-206',
	'status-299',
	'status-304',
	'status-400',
	'status-500',
	'body-5119',
	'body-5120',
	'body-5121',
	'chunked-overflow',
	'content-length-overflow',
	'encoding-gzip',
	'encoding-br',
	'encoding-deflate',
	'content-type-missing',
	'content-type-wrong',
	'content-type-ambiguous',
	'content-type-json',
	'content-type-parameterized',
	'content-type-suffix-json',
	'metadata-nodes-256',
	'metadata-nodes-257',
	'metadata-root-members-64',
	'metadata-root-members-65',
	'metadata-member-name-128',
	'metadata-member-name-129',
	'metadata-string-2048',
	'metadata-string-2049',
	'metadata-client-name-256',
	'metadata-client-name-257',
	'metadata-redirects-32',
	'metadata-redirects-33',
	'metadata-redirect-uri-2048',
	'metadata-redirect-uri-2049',
	'metadata-depth-16',
	'metadata-depth-17',
	'metadata-invalid-utf8',
	'metadata-invalid-json',
	'metadata-duplicate-security',
	'metadata-scalar-root',
	'header-line-8191',
	'header-line-8192',
	'header-line-8193',
	'status-line-8191',
	'status-line-8192',
	'status-line-8193',
	'header-fields-127',
	'header-fields-128',
	'header-fields-129',
	'header-bytes-32767',
	'header-bytes-32768',
	'header-bytes-32769',
	'interim-response',
	'trailer',
);

/**
 * Returns the fixed state directory path without exposing its value.
 *
 * @return string Fixed state directory.
 */
function charter_p3_state_dir(): string {
	$directory = getenv( 'P3_STATE_DIR' );

	if ( ! is_string( $directory ) || '' === $directory || ! is_dir( $directory ) ) {
		throw new RuntimeException( 'P3 fixture state is unavailable.' );
	}

	return $directory;
}

/**
 * Runs one state operation under the fixture lock.
 *
 * @template T
 * @param callable(string): T $operation Locked operation receiving state path.
 * @return T Operation result.
 */
function charter_p3_with_state_lock( callable $operation ): mixed {
	$directory = charter_p3_state_dir();
	$lock      = @fopen( $directory . '/state.lock', 'c+' );

	if ( false === $lock || ! flock( $lock, LOCK_EX ) ) {
		throw new RuntimeException( 'P3 fixture state lock is unavailable.' );
	}

	try {
		return $operation( $directory );
	} finally {
		flock( $lock, LOCK_UN );
		fclose( $lock );
	}
}

/**
 * Returns a zeroed fixed counter set.
 *
 * @return array<string, int>
 */
function charter_p3_zero_counters(): array {
	return array_fill_keys( CHARTER_P3_COUNTERS, 0 );
}

/**
 * Reads the current fixed scenario.
 *
 * @return string Fixed scenario name.
 */
function charter_p3_scenario(): string {
	return charter_p3_with_state_lock(
		static function ( string $directory ): string {
			$scenario = @file_get_contents( $directory . '/scenario' );
			$scenario = is_string( $scenario ) ? trim( $scenario ) : '';

			return in_array( $scenario, CHARTER_P3_SCENARIOS, true ) ? $scenario : 'safe';
		}
	);
}

/**
 * Resets one allowed scenario and every counter atomically.
 *
 * @param string $scenario Fixed scenario name.
 */
function charter_p3_reset( string $scenario ): void {
	if ( ! in_array( $scenario, CHARTER_P3_SCENARIOS, true ) ) {
		throw new InvalidArgumentException( 'Unknown P3 fixture scenario.' );
	}

	charter_p3_with_state_lock(
		static function ( string $directory ) use ( $scenario ): void {
			$counters = json_encode( charter_p3_zero_counters(), JSON_THROW_ON_ERROR );
			if (
				false === @file_put_contents( $directory . '/scenario', $scenario . "\n", LOCK_EX )
				|| false === @file_put_contents( $directory . '/counters.json', $counters . "\n", LOCK_EX )
			) {
				throw new RuntimeException( 'P3 fixture state reset failed.' );
			}
		}
	);
}

/**
 * Adds one to a fixed counter and returns the new value.
 *
 * @param string $counter Fixed counter name.
 * @return int Updated counter value.
 */
function charter_p3_increment( string $counter ): int {
	if ( ! in_array( $counter, CHARTER_P3_COUNTERS, true ) ) {
		throw new InvalidArgumentException( 'Unknown P3 fixture counter.' );
	}

	return charter_p3_with_state_lock(
		static function ( string $directory ) use ( $counter ): int {
			$raw      = @file_get_contents( $directory . '/counters.json' );
			$decoded  = is_string( $raw ) ? json_decode( $raw, true ) : null;
			$counters = charter_p3_zero_counters();

			if ( is_array( $decoded ) ) {
				foreach ( CHARTER_P3_COUNTERS as $name ) {
					if ( is_int( $decoded[ $name ] ?? null ) && $decoded[ $name ] >= 0 ) {
						$counters[ $name ] = $decoded[ $name ];
					}
				}
			}

			++$counters[ $counter ];
			$encoded = json_encode( $counters, JSON_THROW_ON_ERROR );

			if ( false === @file_put_contents( $directory . '/counters.json', $encoded . "\n", LOCK_EX ) ) {
				throw new RuntimeException( 'P3 fixture counter update failed.' );
			}

			return $counters[ $counter ];
		}
	);
}

/**
 * Reads all fixed counters.
 *
 * @return array<string, int>
 */
function charter_p3_counters(): array {
	return charter_p3_with_state_lock(
		static function ( string $directory ): array {
			$raw      = @file_get_contents( $directory . '/counters.json' );
			$decoded  = is_string( $raw ) ? json_decode( $raw, true ) : null;
			$counters = charter_p3_zero_counters();

			if ( is_array( $decoded ) ) {
				foreach ( CHARTER_P3_COUNTERS as $name ) {
					if ( is_int( $decoded[ $name ] ?? null ) && $decoded[ $name ] >= 0 ) {
						$counters[ $name ] = $decoded[ $name ];
					}
				}
			}

			return $counters;
		}
	);
}

/**
 * Emits one fixed JSON control response.
 *
 * @param int                  $status HTTP status.
 * @param array<string, mixed> $record Fixed response.
 */
function charter_p3_control_response( int $status, array $record ): never {
	http_response_code( $status );
	header( 'Content-Type: application/json' );
	header( 'Cache-Control: no-store' );
	$encoded = json_encode( $record, JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR );
	echo $encoded . "\n";
	exit;
}

/**
 * Serves the fixed, body-free control protocol.
 */
function charter_p3_control_main(): never {
	$method = (string) ( $_SERVER['REQUEST_METHOD'] ?? '' );
	$uri    = (string) ( $_SERVER['REQUEST_URI'] ?? '' );
	$path   = parse_url( $uri, PHP_URL_PATH );
	$path   = is_string( $path ) ? $path : '';

	if ( 'GET' === $method && '/health' === $path ) {
		charter_p3_control_response(
			200,
			array(
				'status' => 'ready',
			)
		);
	}

	if ( 'GET' === $method && '/counters' === $path ) {
		charter_p3_control_response(
			200,
			array(
				'status'   => 'ready',
				'scenario' => charter_p3_scenario(),
				'counters' => charter_p3_counters(),
			)
		);
	}

	if ( 'POST' === $method && 1 === preg_match( '#^/scenario/([a-z0-9-]+)$#D', $path, $matches ) ) {
		$scenario = (string) $matches[1];

		if ( in_array( $scenario, CHARTER_P3_SCENARIOS, true ) ) {
			charter_p3_reset( $scenario );
			charter_p3_control_response(
				200,
				array(
					'status'   => 'ready',
					'scenario' => $scenario,
				)
			);
		}
	}

	charter_p3_control_response(
		404,
		array(
			'status'      => 'rejected',
			'reason_code' => 'unknown_control_operation',
		)
	);
}

/**
 * Decodes one DNS qname and advances the packet offset.
 *
 * @param string $packet Bounded DNS query packet.
 * @param int    $offset Mutable packet offset.
 * @return string|null Decoded lower-case qname.
 */
function charter_p3_dns_name( string $packet, int &$offset ): ?string {
	$labels = array();
	$length = strlen( $packet );

	while ( $offset < $length ) {
		$labelLength = ord( $packet[ $offset ] );
		++$offset;

		if ( 0 === $labelLength ) {
			return implode( '.', $labels );
		}

		if ( $labelLength > 63 || $offset + $labelLength > $length ) {
			return null;
		}

		$labels[] = strtolower( substr( $packet, $offset, $labelLength ) );
		$offset  += $labelLength;
	}

	return null;
}

/**
 * Encodes one fixed DNS qname.
 *
 * @param string $name DNS qname.
 * @return string Encoded wire name.
 */
function charter_p3_dns_encode_name( string $name ): string {
	$encoded = '';
	foreach ( explode( '.', $name ) as $label ) {
		$encoded .= chr( strlen( $label ) ) . $label;
	}

	return $encoded . "\0";
}

/**
 * Builds one DNS resource record.
 *
 * @param int    $type DNS record type.
 * @param string $data Fixed record value.
 * @return string Encoded resource record.
 */
function charter_p3_dns_record( int $type, string $data ): string {
	if ( 1 === $type ) {
		$rdata = inet_pton( $data );
	} elseif ( 28 === $type ) {
		$rdata = inet_pton( $data );
	} elseif ( 5 === $type ) {
		$rdata = charter_p3_dns_encode_name( $data );
	} elseif ( 16 === $type ) {
		$rdata = chr( strlen( $data ) ) . $data;
	} else {
		$rdata = false;
	}

	if ( false === $rdata ) {
		throw new RuntimeException( 'P3 DNS fixture record is invalid.' );
	}

	return "\xc0\x0c" . pack( 'nnNn', $type, 1, 0, strlen( $rdata ) ) . $rdata;
}

/**
 * Returns a bounded DNS response, or null for the timeout scenario.
 *
 * @param string $packet Bounded DNS query packet.
 * @return string|null Fixed response, empty rejection, or timeout sentinel.
 */
function charter_p3_dns_response( string $packet ): ?string {
	if ( strlen( $packet ) < 12 || strlen( $packet ) > 16384 ) {
		return '';
	}

	$header = unpack( 'nid/nflags/nqd/nan/nns/nar', substr( $packet, 0, 12 ) );
	if ( ! is_array( $header ) || 1 !== ( $header['qd'] ?? 0 ) ) {
		return '';
	}

	$offset = 12;
	$name   = charter_p3_dns_name( $packet, $offset );
	if ( null === $name || $offset + 4 > strlen( $packet ) ) {
		return '';
	}

	$questionTail = unpack( 'ntype/nclass', substr( $packet, $offset, 4 ) );
	if ( ! is_array( $questionTail ) ) {
		return '';
	}

	$offset += 4;
	$type    = (int) $questionTail['type'];
	$class   = (int) $questionTail['class'];
	charter_p3_increment( 'dns_query' );

	if ( 'client.charter.test' === $name && 1 === $type ) {
		$aQuery = charter_p3_increment( 'dns_client_a' );
	} else {
		$aQuery = 0;
	}

	if ( 'client.charter.test' === $name && 28 === $type ) {
		charter_p3_increment( 'dns_client_aaaa' );
	}

	$scenario = charter_p3_scenario();
	if ( 'dns-timeout' === $scenario ) {
		return null;
	}
	if ( 'dns-aaaa-timeout' === $scenario && 28 === $type ) {
		return null;
	}
	if ( 'dns-staggered-timeout' === $scenario ) {
		usleep( 600000 );
	}

	if ( 'dns-malformed' === $scenario ) {
		return substr( $packet, 0, 7 );
	}

	if ( 'dns-truncated' === $scenario ) {
		$flags = 0x8600 | ( (int) $header['flags'] & 0x0100 );
		return pack( 'nnnnnn', (int) $header['id'], $flags, 1, 0, 0, 0 ) . substr( $packet, 12, $offset - 12 );
	}

	$rcode       = 'dns-nxdomain' === $scenario ? 3 : ( 'dns-servfail' === $scenario ? 2 : 0 );
	$answers     = array();
	$authorities = array();
	$additionals = array();

	if ( 0 === $rcode && 1 === $class ) {
		if ( 1 === $type ) {
			switch ( $name ) {
				case 'redirect.charter.test':
					$answers[] = charter_p3_dns_record( 1, '198.17.0.35' );
					break;
				case 'embedded.charter.test':
					$answers[] = charter_p3_dns_record( 1, '198.17.0.36' );
					break;
				case 'special.charter.test':
					$answers[] = charter_p3_dns_record( 1, '198.18.0.10' );
					break;
				case 'client.charter.test':
					if ( 'dns-cname-loop' === $scenario ) {
						$answers[] = charter_p3_dns_record( 5, 'client.charter.test' );
					} elseif ( 'dns-cname-safe' === $scenario ) {
						$answers[] = charter_p3_dns_record( 5, 'edge.charter.test' );
					} elseif ( 'dns-cname-special' === $scenario ) {
						$answers[] = charter_p3_dns_record( 5, 'special.charter.test' );
					} elseif ( 'dns-mixed' === $scenario ) {
						$answers[] = charter_p3_dns_record( 1, '198.17.0.34' );
						$answers[] = charter_p3_dns_record( 1, '198.18.0.10' );
					} elseif ( 'dns-rebind' === $scenario && $aQuery > 1 ) {
						$answers[] = charter_p3_dns_record( 1, '198.18.0.10' );
					} elseif ( 'dns-sibling' === $scenario ) {
						$answers[] = charter_p3_dns_record( 1, $aQuery > 1 ? '198.17.0.35' : '198.17.0.34' );
					} elseif ( 'dns-safe-reorder' === $scenario ) {
						$ordered = $aQuery > 1
							? array( array( 28, '2001:4860:ffff::34' ), array( 1, '198.17.0.34' ) )
							: array( array( 1, '198.17.0.34' ), array( 28, '2001:4860:ffff::34' ) );
						foreach ( $ordered as $record ) {
							$answers[] = charter_p3_dns_record( $record[0], $record[1] );
						}
					} else {
						$answers[] = charter_p3_dns_record( 1, '198.17.0.34' );
					}
					if ( in_array( $scenario, array( 'dns-sections-64', 'dns-sections-65' ), true ) ) {
						$authorityCount = 'dns-sections-64' === $scenario ? 31 : 32;
						for ( $index = 0; $index < $authorityCount; ++$index ) {
							$authorities[] = charter_p3_dns_record( 16, 'proof' );
						}
						for ( $index = 0; $index < 32; ++$index ) {
							$additionals[] = charter_p3_dns_record( 16, 'proof' );
						}
					}
					break;
				case 'edge.charter.test':
					$answers[] = charter_p3_dns_record( 1, '198.17.0.34' );
					break;
			}
		}
	}

	$flags     = 0x8400 | ( (int) $header['flags'] & 0x0100 ) | $rcode;
	$response  = pack( 'nnnnnn', (int) $header['id'], $flags, 1, count( $answers ), count( $authorities ), count( $additionals ) );
	$response .= substr( $packet, 12, $offset - 12 );
	$response .= implode( '', $answers );
	$response .= implode( '', $authorities );
	$response .= implode( '', $additionals );
	if ( 'dns-trailing-data' === $scenario ) {
		$response .= "\0";
	}

	return $response;
}

/**
 * Runs the authoritative UDP and TCP DNS fixture.
 */
function charter_p3_dns_main(): never {
	$listen = getenv( 'P3_DNS_LISTEN' );
	$listen = is_string( $listen ) && '' !== $listen ? $listen : '0.0.0.0:8053';
	$udp    = @stream_socket_server( 'udp://' . $listen, $errorNumber, $errorMessage, STREAM_SERVER_BIND );
	$tcp    = @stream_socket_server( 'tcp://' . $listen, $errorNumber, $errorMessage, STREAM_SERVER_BIND | STREAM_SERVER_LISTEN );
	unset( $errorNumber, $errorMessage );

	if ( false === $udp || false === $tcp ) {
		throw new RuntimeException( 'P3 DNS fixture failed to bind.' );
	}
	stream_set_blocking( $udp, false );
	stream_set_blocking( $tcp, false );

	while ( true ) {
		$read   = array( $udp, $tcp );
		$write  = null;
		$except = null;
		if ( false === @stream_select( $read, $write, $except, 1 ) ) {
			continue;
		}

		foreach ( $read as $socket ) {
			if ( $socket === $udp ) {
				$peer   = '';
				$packet = @stream_socket_recvfrom( $udp, 16384, 0, $peer );

				if ( ! is_string( $packet ) || '' === $packet || '' === $peer ) {
					continue;
				}

				$response = charter_p3_dns_response( $packet );
				if ( null !== $response && '' !== $response ) {
					@stream_socket_sendto( $udp, $response, 0, $peer );
				}
				continue;
			}

			$connection = @stream_socket_accept( $tcp, 0 );
			if ( false === $connection ) {
				continue;
			}
			stream_set_timeout( $connection, 1 );
			$lengthBytes = @fread( $connection, 2 );
			$lengthData  = is_string( $lengthBytes ) && 2 === strlen( $lengthBytes ) ? unpack( 'nlength', $lengthBytes ) : false;
			$length      = is_array( $lengthData ) ? (int) $lengthData['length'] : 0;
			$packet      = $length > 0 && $length <= 16384 ? @fread( $connection, $length ) : false;

			if ( is_string( $packet ) && strlen( $packet ) === $length ) {
				$response = charter_p3_dns_response( $packet );
				if ( null !== $response && '' !== $response ) {
					@fwrite( $connection, pack( 'n', strlen( $response ) ) . $response );
				}
			}
			fclose( $connection );
		}
	}
}

/**
 * Returns the exact fixture metadata body.
 *
 * @param bool $embeddedUrls Whether inert embedded URLs are included.
 * @return string Exact JSON document.
 */
function charter_p3_metadata_body( bool $embeddedUrls = false ): string {
	$document = array(
		'client_id'                  => 'https://client.charter.test/client.json',
		'client_name'                => 'Charter P3 proof client',
		'redirect_uris'              => array( 'https://app.charter.test/callback' ),
		'token_endpoint_auth_method' => 'none',
	);

	if ( $embeddedUrls ) {
		$document['client_uri'] = 'https://embedded.charter.test/client';
		$document['logo_uri']   = 'https://embedded.charter.test/logo';
		$document['jwks_uri']   = 'https://embedded.charter.test/jwks';
	}

	return json_encode( $document, JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR );
}

/**
 * Returns one exact metadata structural-boundary response body.
 *
 * @param string $scenario Fixed metadata scenario.
 * @return string JSON or deliberately invalid JSON bytes.
 */
function charter_p3_metadata_scenario_body( string $scenario ): string {
	$document = array(
		'client_id'                  => 'https://client.charter.test/client.json',
		'client_name'                => 'Charter P3 proof client',
		'redirect_uris'              => array( 'https://app.charter.test/callback' ),
		'token_endpoint_auth_method' => 'none',
	);

	if ( 1 === preg_match( '/^metadata-nodes-(256|257)$/D', $scenario, $matches ) ) {
		$document['shape'] = array_fill( 0, (int) $matches[1] - 7, 0 );
	} elseif ( 1 === preg_match( '/^metadata-root-members-(64|65)$/D', $scenario, $matches ) ) {
		for ( $index = 0; $index < (int) $matches[1] - 4; ++$index ) {
			$document[ 'inert_' . $index ] = $index;
		}
	} elseif ( 1 === preg_match( '/^metadata-member-name-(128|129)$/D', $scenario, $matches ) ) {
		$document[ str_repeat( 'k', (int) $matches[1] ) ] = 0;
	} elseif ( 1 === preg_match( '/^metadata-string-(2048|2049)$/D', $scenario, $matches ) ) {
		$document['description'] = str_repeat( 'g', (int) $matches[1] );
	} elseif ( 1 === preg_match( '/^metadata-client-name-(256|257)$/D', $scenario, $matches ) ) {
		$document['client_name'] = str_repeat( 'n', (int) $matches[1] );
	} elseif ( 1 === preg_match( '/^metadata-redirects-(32|33)$/D', $scenario, $matches ) ) {
		$document['redirect_uris'] = array();
		for ( $index = 0; $index < (int) $matches[1]; ++$index ) {
			$document['redirect_uris'][] = 'https://app.charter.test/callback/' . $index;
		}
	} elseif ( 1 === preg_match( '/^metadata-redirect-uri-(2048|2049)$/D', $scenario, $matches ) ) {
		$prefix                    = 'https://app.charter.test/';
		$document['redirect_uris'] = array( $prefix . str_repeat( 'r', (int) $matches[1] - strlen( $prefix ) ) );
	} elseif ( 1 === preg_match( '/^metadata-depth-(16|17)$/D', $scenario, $matches ) ) {
		$value      = array();
		$arrayCount = (int) $matches[1] - 1;
		for ( $depth = 1; $depth < $arrayCount; ++$depth ) {
			$value = array( $value );
		}
		$document['shape'] = $value;
	} elseif ( 'metadata-invalid-utf8' === $scenario ) {
		return '{"client_id":"https://client.charter.test/client.json","client_name":"' . "\xff" . '"}';
	} elseif ( 'metadata-invalid-json' === $scenario ) {
		return '{"client_id":"https://client.charter.test/client.json"';
	} elseif ( 'metadata-duplicate-security' === $scenario ) {
		return '{"client_id":"https://client.charter.test/client.json",'
			. '"client_name":"Charter P3 proof client",'
			. '"redirect_uris":["https://app.charter.test/callback"],'
			. '"redirect_uris":["https://other.charter.test/callback"],'
			. '"token_endpoint_auth_method":"none"}';
	} elseif ( 'metadata-scalar-root' === $scenario ) {
		return '"scalar"';
	}

	return json_encode( $document, JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR );
}

/**
 * Builds a response whose complete header callback bytes equal one target.
 *
 * The aggregate includes the status line, every field line, and the empty
 * delimiter line. Individual padding lines stay far below the separate 8,192
 * byte line limit, and the field count stays below 128, so this fixture
 * isolates only the aggregate-byte boundary.
 *
 * @param int    $target Exact aggregate header bytes.
 * @param string $body   Fixed response body.
 * @return string Exact HTTP response wire image.
 */
function charter_p3_exact_header_bytes_response( int $target, string $body ): string {
	$head      = "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n";
	$tail      = 'Content-Length: ' . strlen( $body ) . "\r\nConnection: close\r\n\r\n";
	$remaining = $target - strlen( $head ) - strlen( $tail );

	if ( $remaining < 32 ) {
		throw new RuntimeException( 'P3 aggregate-header fixture target is too small.' );
	}

	$lineCount = (int) ceil( $remaining / 4096 );
	for ( $index = 0; $index < $lineCount; ++$index ) {
		$linesRemaining = $lineCount - $index;
		$lineBytes      = intdiv( $remaining, $linesRemaining );
		$prefix         = sprintf( 'X-P3-Aggregate-%03d: ', $index );
		$valueBytes     = $lineBytes - strlen( $prefix ) - 2;

		if ( $valueBytes < 1 || $lineBytes > 4096 ) {
			throw new RuntimeException( 'P3 aggregate-header fixture could not isolate the requested boundary.' );
		}

		$head      .= $prefix . str_repeat( 'b', $valueBytes ) . "\r\n";
		$remaining -= $lineBytes;
	}

	// phpcs:ignore WordPress.PHP.YodaConditions.NotYoda -- Both sides are runtime lengths.
	if ( 0 !== $remaining || $target !== strlen( $head . $tail ) ) {
		throw new RuntimeException( 'P3 aggregate-header fixture length is not exact.' );
	}

	return $head . $tail . $body;
}

/**
 * Builds one response with an exact status-line callback length.
 *
 * @param int    $target Exact status-line bytes including CRLF.
 * @param string $body   Fixed response body.
 * @return string Exact HTTP response wire image.
 */
function charter_p3_exact_status_line_response( int $target, string $body ): string {
	$prefix      = 'HTTP/1.1 200 ';
	$reasonBytes = $target - strlen( $prefix ) - 2;

	if ( $reasonBytes < 1 ) {
		throw new RuntimeException( 'P3 status-line fixture target is too small.' );
	}

	return $prefix . str_repeat( 'P', $reasonBytes ) . "\r\n"
		. "Content-Type: application/json\r\nContent-Length: " . strlen( $body )
		. "\r\nConnection: close\r\n\r\n" . $body;
}

/**
 * Checks the fixed outbound request policy without retaining request material.
 *
 * The disposable fixture accepts the candidate User-Agent and the separate
 * mechanism-probe User-Agent. Every other required header is exact, and only
 * Host and Connection may be added by the HTTP transport.
 *
 * @param string $request Bounded transient HTTP request.
 * @return bool Whether the request matches the fixed egress profile.
 */
function charter_p3_request_policy_matches( string $request ): bool {
	$parts = explode( "\r\n\r\n", $request, 2 );
	if ( 2 !== count( $parts ) || '' !== $parts[1] ) {
		return false;
	}

	$lines = explode( "\r\n", $parts[0] );
	$start = array_shift( $lines );
	if ( 'GET /client.json HTTP/1.1' !== $start ) {
		return false;
	}

	$headers = array();
	foreach ( $lines as $line ) {
		$colon = strpos( $line, ':' );
		if ( false === $colon ) {
			return false;
		}

		$name               = strtolower( trim( substr( $line, 0, $colon ) ) );
		$headers[ $name ][] = trim( substr( $line, $colon + 1 ) );
	}

	$expected = array(
		'host'            => array( 'client.charter.test' ),
		'accept'          => array( 'application/json' ),
		'accept-encoding' => array( 'identity' ),
		'cache-control'   => array( 'no-cache' ),
	);
	foreach ( $expected as $name => $values ) {
		// phpcs:ignore WordPress.PHP.YodaConditions.NotYoda -- Both sides are runtime lists.
		if ( $values !== ( $headers[ $name ] ?? null ) ) {
			return false;
		}
	}

	$userAgent = $headers['user-agent'] ?? null;
	if (
		! is_array( $userAgent )
		|| 1 !== count( $userAgent )
		|| ! in_array( $userAgent[0], array( 'Charter-CIMD-Proof/1', 'Charter-CIMD/0.1', 'Charter-P3-Probe/1' ), true )
	) {
		return false;
	}

	$allowed = array( 'host', 'accept', 'accept-encoding', 'cache-control', 'user-agent', 'connection' );
	foreach ( array_keys( $headers ) as $name ) {
		if ( ! in_array( $name, $allowed, true ) ) {
			return false;
		}
	}

	return ! isset( $headers['connection'] ) || array( 'close' ) === $headers['connection'];
}

/**
 * Returns scenario response components.
 *
 * @param string $scenario Fixed scenario name.
 * @return array{status: int, headers: list<string>, body: string, raw: string|null, delay_before_tls: int, delay_before_body: int, slow_body: bool, early_close: bool}
 */
function charter_p3_origin_response( string $scenario ): array {
	$body    = str_starts_with( $scenario, 'metadata-' )
		? charter_p3_metadata_scenario_body( $scenario )
		: charter_p3_metadata_body( 'embedded-urls' === $scenario );
	$status  = 200;
	$headers = array( 'Content-Type: application/json', 'Cache-Control: max-age=300' );
	$raw     = null;

	if ( 1 === preg_match( '/^status-(\d{3})$/D', $scenario, $matches ) ) {
		$status = (int) $matches[1];
	}

	$redirects = array(
		'redirect-public'      => 'https://redirect.charter.test/client.json',
		'redirect-loopback'    => 'https://127.0.0.1/client.json',
		'redirect-private'     => 'https://10.0.0.1/client.json',
		'redirect-special'     => 'https://special.charter.test/client.json',
		'redirect-http'        => 'http://redirect.charter.test/client.json',
		'redirect-port'        => 'https://redirect.charter.test:8443/client.json',
		'redirect-credentials' => 'https://proof@redirect.charter.test/client.json',
		'redirect-malformed'   => 'https://[invalid/client.json',
		'redirect-long'        => 'https://redirect.charter.test/' . str_repeat( 'l', 8100 ),
	);

	if ( isset( $redirects[ $scenario ] ) ) {
		$status    = 302;
		$headers[] = 'Location: ' . $redirects[ $scenario ];
		$body      = '';
	}

	if ( 1 === preg_match( '/^body-(5119|5120|5121)$/D', $scenario, $matches ) ) {
		$target = (int) $matches[1];
		$body   = str_pad( charter_p3_metadata_body(), $target, ' ' );
	}

	if ( 'slow-body' === $scenario ) {
		$body = str_pad( charter_p3_metadata_body(), 5120, ' ' );
	}

	if ( 'content-length-overflow' === $scenario ) {
		$headers[] = 'Content-Length: 5121';
	}

	if ( 'chunked-overflow' === $scenario ) {
		$payload = str_pad( charter_p3_metadata_body(), 5121, ' ' );
		$raw     = "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nTransfer-Encoding: chunked\r\n\r\n"
			. dechex( strlen( $payload ) ) . "\r\n" . $payload . "\r\n0\r\n\r\n";
	}

	if ( in_array( $scenario, array( 'encoding-gzip', 'encoding-br', 'encoding-deflate' ), true ) ) {
		$headers[] = 'Content-Encoding: ' . substr( $scenario, strlen( 'encoding-' ) );
	}

	if ( 'valid-json-prefix-truncated' === $scenario ) {
		$raw = "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: " . strlen( $body )
			. "\r\n\r\n" . substr( $body, 0, -1 );
	}

	if ( 'content-type-missing' === $scenario ) {
		$headers = array_values( array_filter( $headers, static fn ( string $header ): bool => ! str_starts_with( $header, 'Content-Type:' ) ) );
	} elseif ( 'content-type-wrong' === $scenario ) {
		$headers[0] = 'Content-Type: text/json';
	} elseif ( 'content-type-ambiguous' === $scenario ) {
		$headers[] = 'Content-Type: application/problem+json';
	} elseif ( 'content-type-parameterized' === $scenario ) {
		$headers[0] = 'Content-Type: Application/JSON; charset=utf-8';
	} elseif ( 'content-type-suffix-json' === $scenario ) {
		$headers[0] = 'Content-Type: application/client-metadata+json';
	}

	if ( 1 === preg_match( '/^header-line-(8191|8192|8193)$/D', $scenario, $matches ) ) {
		$lineLength = (int) $matches[1];
		$headers[]  = 'X-P3-Padding: ' . str_repeat( 'a', max( 0, $lineLength - 16 ) );
	}

	if ( 1 === preg_match( '/^status-line-(8191|8192|8193)$/D', $scenario, $matches ) ) {
		$raw = charter_p3_exact_status_line_response( (int) $matches[1], $body );
	}

	if ( 1 === preg_match( '/^header-fields-(127|128|129)$/D', $scenario, $matches ) ) {
		$fieldCount = (int) $matches[1];
		$headers    = array();
		// Content-Type plus the generated Content-Length and Connection fields
		// below are part of the advertised callback field total.
		for ( $index = 0; $index < $fieldCount - 3; ++$index ) {
			$headers[] = sprintf( 'X-P3-%03d: 1', $index );
		}
		$headers[] = 'Content-Type: application/json';
	}

	if ( 1 === preg_match( '/^header-bytes-(32767|32768|32769)$/D', $scenario, $matches ) ) {
		$raw = charter_p3_exact_header_bytes_response( (int) $matches[1], $body );
	}

	if ( 'interim-response' === $scenario ) {
		$raw = "HTTP/1.1 103 Early Hints\r\nLink: </proof>; rel=preload\r\n\r\n"
			. "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: " . strlen( $body ) . "\r\n\r\n" . $body;
	}

	if ( 'trailer' === $scenario ) {
		$raw = "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nTransfer-Encoding: chunked\r\nTrailer: X-P3-Trailer\r\n\r\n"
			. dechex( strlen( $body ) ) . "\r\n" . $body . "\r\n0\r\nX-P3-Trailer: observed\r\n\r\n";
	}

	return array(
		'status'            => $status,
		'headers'           => $headers,
		'body'              => $body,
		'raw'               => $raw,
		'delay_before_tls'  => 'tls-delay' === $scenario ? 4 : 0,
		'delay_before_body' => 'first-byte-delay' === $scenario ? 6 : 0,
		'slow_body'         => 'slow-body' === $scenario,
		'early_close'       => 'early-close' === $scenario,
	);
}

/**
 * Increments role-specific network counters.
 *
 * @param string $role  Fixed fixture role.
 * @param string $phase Fixed counter phase.
 */
function charter_p3_role_counter( string $role, string $phase ): void {
	charter_p3_increment( $phase );

	if ( 'origin' === $role ) {
		charter_p3_increment( 'origin_' . $phase );
	} elseif ( 'special' === $role ) {
		charter_p3_increment( 'special_' . $phase );
	}

	if ( 'http_request' === $phase && 'redirect-target' === $role ) {
		charter_p3_increment( 'redirect_target' );
	} elseif ( 'http_request' === $phase && 'embedded-url' === $role ) {
		charter_p3_increment( 'embedded_url' );
	}
}

/**
 * Handles one bounded TLS connection.
 *
 * @param resource $connection Accepted socket.
 * @param string   $role       Fixed fixture role.
 */
function charter_p3_origin_connection( $connection, string $role ): void {
	charter_p3_role_counter( $role, 'tcp_connection' );
	stream_set_timeout( $connection, 7 );
	$response = charter_p3_origin_response( charter_p3_scenario() );

	if ( $response['delay_before_tls'] > 0 ) {
		sleep( $response['delay_before_tls'] );
	}

	if ( true !== @stream_socket_enable_crypto( $connection, true, STREAM_CRYPTO_METHOD_TLS_SERVER ) ) {
		return;
	}

	charter_p3_role_counter( $role, 'tls_handshake' );
	$request       = '';
	$requestLength = 0;
	while ( $requestLength <= 32768 && ! str_contains( $request, "\r\n\r\n" ) ) {
		$chunk = @fread( $connection, 1024 );
		if ( ! is_string( $chunk ) || '' === $chunk ) {
			break;
		}
		$request       .= $chunk;
		$requestLength += strlen( $chunk );
	}

	if ( '' === $request ) {
		return;
	}

	charter_p3_role_counter( $role, 'http_request' );
	if ( ! charter_p3_request_policy_matches( $request ) ) {
		charter_p3_increment( 'sensitive_egress' );
	}

	if ( $response['early_close'] ) {
		return;
	}

	if ( $response['delay_before_body'] > 0 ) {
		sleep( $response['delay_before_body'] );
	}

	if ( is_string( $response['raw'] ) ) {
		@fwrite( $connection, $response['raw'] );
		return;
	}

	$phrases = array(
		199 => 'Informational',
		200 => 'OK',
		204 => 'No Content',
		206 => 'Partial Content',
		299 => 'Proof',
		302 => 'Found',
		304 => 'Not Modified',
		400 => 'Bad Request',
		500 => 'Internal Server Error',
	);
	$status  = $response['status'];
	$body    = $response['body'];
	$headers = $response['headers'];

	if ( ! in_array( 'Content-Length: ' . strlen( $body ), $headers, true ) && 'content-length-overflow' !== charter_p3_scenario() ) {
		$headers[] = 'Content-Length: ' . strlen( $body );
	}
	$headers[] = 'Connection: close';
	$wire      = 'HTTP/1.1 ' . $status . ' ' . ( $phrases[ $status ] ?? 'Proof' ) . "\r\n" . implode( "\r\n", $headers ) . "\r\n\r\n";
	@fwrite( $connection, $wire );

	if ( $response['slow_body'] ) {
		foreach ( str_split( $body, 64 ) as $chunk ) {
			if ( strlen( $chunk ) !== @fwrite( $connection, $chunk ) ) {
				break;
			}
			usleep( 200000 );
		}
	} else {
		@fwrite( $connection, $body );
	}
}

/**
 * Runs a TLS origin or negative sink fixture.
 *
 * @param string $role Fixed fixture role.
 */
function charter_p3_origin_main( string $role ): never {
	if ( ! in_array( $role, array( 'origin', 'redirect-target', 'embedded-url', 'special' ), true ) ) {
		throw new RuntimeException( 'P3 origin role is invalid.' );
	}

	$listen  = getenv( 'P3_LISTEN' );
	$certDir = getenv( 'P3_CERT_DIR' );
	if ( ! is_string( $listen ) || '' === $listen || ! is_string( $certDir ) || '' === $certDir ) {
		throw new RuntimeException( 'P3 origin configuration is unavailable.' );
	}

	$context = stream_context_create(
		array(
			'ssl' => array(
				'local_cert'          => $certDir . '/server.crt',
				'local_pk'            => $certDir . '/server.key',
				'disable_compression' => true,
				'crypto_method'       => STREAM_CRYPTO_METHOD_TLS_SERVER,
			),
		)
	);
	$server  = @stream_socket_server( 'tcp://' . $listen, $errorNumber, $errorMessage, STREAM_SERVER_BIND | STREAM_SERVER_LISTEN, $context );
	unset( $errorNumber, $errorMessage );

	if ( false === $server ) {
		throw new RuntimeException( 'P3 origin fixture failed to bind.' );
	}

	while ( true ) {
		$connection = @stream_socket_accept( $server, -1 );
		if ( false === $connection ) {
			continue;
		}

		try {
			charter_p3_origin_connection( $connection, $role );
		} finally {
			fclose( $connection );
		}
	}
}

/**
 * Executes the one proof-owned unsafe-proxy red contact.
 *
 * The proxy deliberately maps the exact original client target to the
 * special-use sink. It sends only the fixed credential-free proof request,
 * never forwards caller headers or a request body, and discards the bounded
 * response without retaining or emitting it.
 *
 * @return bool Whether the complete TLS request was sent.
 */
function charter_p3_proxy_contact_special(): bool {
	$caFile = getenv( 'P3_CA_FILE' );
	if ( ! is_string( $caFile ) || ! is_file( $caFile ) ) {
		return false;
	}

	$context = stream_context_create(
		array(
			'ssl' => array(
				'cafile'            => $caFile,
				'peer_name'         => 'client.charter.test',
				'verify_peer'       => true,
				'verify_peer_name'  => true,
				'allow_self_signed' => false,
			),
		)
	);
	$socket  = @stream_socket_client( 'tls://198.18.0.10:443', $number, $message, 2, STREAM_CLIENT_CONNECT, $context );
	unset( $number, $message );
	if ( false === $socket ) {
		return false;
	}

	stream_set_timeout( $socket, 2 );
	$request = "GET /client.json HTTP/1.1\r\n"
		. "Host: client.charter.test\r\n"
		. "Accept: application/json\r\n"
		. "Accept-Encoding: identity\r\n"
		. "Cache-Control: no-cache\r\n"
		. "User-Agent: Charter-P3-Probe/1\r\n"
		. "Connection: close\r\n\r\n";
	$sent    = strlen( $request ) === @fwrite( $socket, $request );
	$bytes   = 0;
	while ( $sent && ! feof( $socket ) && $bytes < 8192 ) {
		$chunk = @fread( $socket, min( 1024, 8192 - $bytes ) );
		if ( ! is_string( $chunk ) || '' === $chunk ) {
			break;
		}
		$bytes += strlen( $chunk );
	}
	fclose( $socket );

	return $sent;
}

/**
 * Runs an HTTP/CONNECT or SOCKS expected-red proxy observation sink.
 *
 * @param string $protocol Fixed proxy protocol.
 */
function charter_p3_proxy_main( string $protocol ): never {
	if ( ! in_array( $protocol, array( 'http', 'socks' ), true ) ) {
		throw new RuntimeException( 'P3 proxy protocol is invalid.' );
	}

	$listen = getenv( 'P3_LISTEN' );
	if ( ! is_string( $listen ) || '' === $listen ) {
		throw new RuntimeException( 'P3 proxy configuration is unavailable.' );
	}

	$server = @stream_socket_server( 'tcp://' . $listen, $errorNumber, $errorMessage, STREAM_SERVER_BIND | STREAM_SERVER_LISTEN );
	unset( $errorNumber, $errorMessage );

	if ( false === $server ) {
		throw new RuntimeException( 'P3 proxy fixture failed to bind.' );
	}

	while ( true ) {
		$connection = @stream_socket_accept( $server, -1 );
		if ( false === $connection ) {
			continue;
		}

		charter_p3_increment( 'proxy' );
		charter_p3_increment( $protocol . '_proxy_connection' );
		stream_set_timeout( $connection, 1 );

		$recognized = false;
		if ( 'http' === $protocol ) {
			$request    = @fread( $connection, 1024 );
			$recognized = is_string( $request ) && 1 === preg_match(
				'#^(?:GET https://client\.charter\.test/client\.json|CONNECT client\.charter\.test:443) HTTP/1\.1\r\n#D',
				$request
			);
			if ( $recognized ) {
				$recognized = charter_p3_proxy_contact_special();
			}
			@fwrite( $connection, "HTTP/1.1 502 Proof Proxy Rejected\r\nContent-Length: 0\r\nConnection: close\r\n\r\n" );
		} else {
			$greeting = @fread( $connection, 258 );
			if ( is_string( $greeting ) && str_starts_with( $greeting, "\x05" ) ) {
				@fwrite( $connection, "\x05\x00" );
				$request    = @fread( $connection, 512 );
				$recognized = is_string( $request ) && (
					"\x05\x01\x00\x01" . inet_pton( '198.18.0.10' ) . pack( 'n', 443 ) === $request
					|| "\x05\x01\x00\x03" . chr( strlen( 'client.charter.test' ) ) . 'client.charter.test' . pack( 'n', 443 ) === $request
				);
				if ( $recognized ) {
					$recognized = charter_p3_proxy_contact_special();
				}
				@fwrite( $connection, $recognized ? "\x05\x00\x00\x01\x0a\x4d\x00\x0a\x01\xbb" : "\x05\x02\x00\x01\x00\x00\x00\x00\x00\x00" );
			} else {
				@fwrite( $connection, "\x05\xff" );
			}
		}

		fclose( $connection );
	}
}
