<?php
/**
 * Validates and sanitizes disposable P5 HTTP captures.
 *
 * @package GalatanOvidiu\Charter
 */

declare(strict_types=1);

const CHARTER_P5_MAX_HEADER_BYTES = 16384;
const CHARTER_P5_MAX_BODY_BYTES   = 65536;

/**
 * Exits with a bounded failure message.
 *
 * @param string $message The non-secret failure message.
 */
function charter_p5_fail( string $message ): never {
	// phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_fwrite -- Writes only a bounded error to STDERR.
	fwrite( STDERR, 'P5 output validation failed: ' . $message . PHP_EOL );
	exit( 1 );
}

/**
 * Returns one required CLI option.
 *
 * @param array<string, string|false> $options The parsed options.
 * @param string                      $name    The option name.
 * @return string The option value.
 */
function charter_p5_option( array $options, string $name ): string {
	$value = $options[ $name ] ?? false;

	if ( ! is_string( $value ) || '' === $value ) {
		charter_p5_fail( 'missing required option ' . $name );
	}

	return $value;
}

/**
 * Parses a curl header capture into lower-case fields.
 *
 * @param string $rawHeaders The bounded raw header capture.
 * @return array{status: int, fields: array<string, string>} Parsed headers.
 */
function charter_p5_parse_headers( string $rawHeaders ): array {
	$blocks = preg_split( "/\r?\n\r?\n/", trim( $rawHeaders ) );

	if ( ! is_array( $blocks ) || array() === $blocks ) {
		charter_p5_fail( 'header capture is empty' );
	}

	$block = (string) end( $blocks );
	$lines = preg_split( "/\r?\n/", $block );

	if ( ! is_array( $lines ) || ! isset( $lines[0] ) || 1 !== preg_match( '/^HTTP\/\S+\s+(\d{3})\b/', $lines[0], $matches ) ) {
		charter_p5_fail( 'status line is invalid' );
	}

	$fields = array();
	$criticalSingletons = array(
		'content-type',
		'location',
		'access-control-allow-origin',
		'access-control-allow-credentials',
		'cache-control',
		'content-location',
		'x-charter-proof-front-controller-reached',
		'x-charter-proof-wordpress-version',
	);

	foreach ( array_slice( $lines, 1 ) as $line ) {
		if ( ! str_contains( $line, ':' ) ) {
			continue;
		}

		list( $name, $value ) = explode( ':', $line, 2 );
		$name                 = strtolower( trim( $name ) );

		if ( in_array( $name, $criticalSingletons, true ) && array_key_exists( $name, $fields ) ) {
			charter_p5_fail( 'the response did not match the exact HTTP contract' );
		}

		$fields[ $name ] = trim( $value );
	}

	return array(
		'status' => (int) $matches[1],
		'fields' => $fields,
	);
}

/**
 * Returns the exact metadata document required at one supported URL.
 *
 * @param string $requestedUrl     The exact requested metadata URL.
 * @param string $expectedIdentity The exact issuer or resource identity.
 * @return array<string, string|list<string>>|null The expected document, or null for a non-metadata URL.
 */
function charter_p5_expected_metadata( string $requestedUrl, string $expectedIdentity ): ?array {
	// phpcs:ignore WordPress.WP.AlternativeFunctions.parse_url_parse_url -- Standalone proof tool does not bootstrap WordPress functions.
	$parts = parse_url( $requestedUrl );

	if (
		! is_array( $parts )
		|| 'https' !== ( $parts['scheme'] ?? null )
		|| ! is_string( $parts['host'] ?? null )
		|| '' === $expectedIdentity
		|| isset( $parts['user'] )
		|| isset( $parts['pass'] )
		|| isset( $parts['query'] )
		|| isset( $parts['fragment'] )
	) {
		return null;
	}

	$issuer = 'https://' . $parts['host'];

	if ( isset( $parts['port'] ) ) {
		$issuer .= ':' . $parts['port'];
	}

	$path = $parts['path'] ?? '';

	if ( '/.well-known/oauth-authorization-server' === $path ) {
		return array(
			'issuer'                                     => $expectedIdentity,
			'authorization_endpoint'                     => $expectedIdentity . '/charter-proof/authorize',
			'token_endpoint'                             => $expectedIdentity . '/charter-proof/token',
			'registration_endpoint'                      => $expectedIdentity . '/charter-proof/register',
			'revocation_endpoint'                        => $expectedIdentity . '/charter-proof/revoke',
			'response_types_supported'                   => array( 'code' ),
			'response_modes_supported'                   => array( 'query' ),
			'grant_types_supported'                      => array( 'authorization_code', 'refresh_token' ),
			'token_endpoint_auth_methods_supported'      => array( 'none', 'client_secret_post' ),
			'revocation_endpoint_auth_methods_supported' => array( 'none', 'client_secret_post' ),
			'code_challenge_methods_supported'           => array( 'S256' ),
			'scopes_supported'                           => array( 'wordpress:access', 'offline_access' ),
		);
	}

	if (
		'/.well-known/oauth-protected-resource' === $path
		|| str_starts_with( $path, '/.well-known/oauth-protected-resource/' )
	) {
		return array(
			'resource'              => $expectedIdentity,
			'authorization_servers' => array( $issuer ),
		);
	}

	return null;
}

/**
 * Runs the standalone fixed-schema validator.
 */
function charter_p5_main(): void {
	$options = getopt(
		'',
		array(
			'lane:',
				'state:',
				'process-mode:',
			'url:',
			'expected-status:',
			'expected-identity:',
			'expected-reached:',
			'headers:',
			'body:',
		)
	);

	if ( ! is_array( $options ) ) {
		charter_p5_fail( 'options could not be parsed' );
	}

	$headersPath           = charter_p5_option( $options, 'headers' );
	$bodyPath              = charter_p5_option( $options, 'body' );
	$expectedStatus        = (int) charter_p5_option( $options, 'expected-status' );
	$expectedIdentity      = (string) ( $options['expected-identity'] ?? '' );
	$expectedReachedOption = charter_p5_option( $options, 'expected-reached' );
	$expectedReached       = 'true' === $expectedReachedOption;

	if ( ! in_array( $expectedReachedOption, array( 'true', 'false', 'any' ), true ) ) {
		charter_p5_fail( 'expected-reached must be true, false, or any' );
	}

// phpcs:ignore WordPress.WP.AlternativeFunctions.file_get_contents_file_get_contents -- Reads a private bounded proof capture.
	$rawHeaders = file_get_contents( $headersPath );
// phpcs:ignore WordPress.WP.AlternativeFunctions.file_get_contents_file_get_contents -- Reads a private bounded proof capture.
	$rawBody = file_get_contents( $bodyPath );

	if ( ! is_string( $rawHeaders ) || ! is_string( $rawBody ) ) {
		charter_p5_fail( 'capture files could not be read' );
	}

	if ( strlen( $rawHeaders ) > CHARTER_P5_MAX_HEADER_BYTES || strlen( $rawBody ) > CHARTER_P5_MAX_BODY_BYTES ) {
		charter_p5_fail( 'capture exceeds the fixed byte limit' );
	}

	if (
	1 === preg_match( '/^(authorization|proxy-authorization|set-cookie|cookie):/mi', $rawHeaders )
	|| 1 === preg_match( '/\b(?:Bearer|Basic)\s+[A-Za-z0-9._~+\/-]+=*/i', $rawHeaders . "\n" . $rawBody )
	|| 1 === preg_match( '/"(?:access_token|refresh_token|client_secret|authorization_code)"\s*:/i', $rawBody )
	) {
		charter_p5_fail( 'secret-like material appeared in the capture' );
	}

	$parsedHeaders = charter_p5_parse_headers( $rawHeaders );
	$fields        = $parsedHeaders['fields'];
	$contentType   = strtolower( $fields['content-type'] ?? '' );
	$json          = json_decode( $rawBody, true );
	$bodyClass     = '' === $rawBody ? 'empty' : 'text';

	if ( is_array( $json ) ) {
		$bodyClass = 'json';
	} elseif ( str_contains( strtolower( $rawBody ), '<!doctype html' ) || str_contains( strtolower( $rawBody ), '<html' ) ) {
		$bodyClass = 'html';
	}

	$contentTypeClass = 'other';

	if ( 1 === preg_match( '/^(application\/json|text\/html|text\/plain)(?:\s*;|$)/D', $contentType, $contentTypeMatches ) ) {
		$contentTypeClass = $contentTypeMatches[1];
	}

	$identity = '';

	if ( is_array( $json ) ) {
		if ( is_string( $json['issuer'] ?? null ) ) {
			$identity = $json['issuer'];
		} elseif ( is_string( $json['resource'] ?? null ) ) {
			$identity = $json['resource'];
		}
	}

	$requestedUrl     = charter_p5_option( $options, 'url' );
	$expectedMetadata = charter_p5_expected_metadata( $requestedUrl, $expectedIdentity );
	$metadataMatch    = is_array( $json ) && is_array( $expectedMetadata ) && $expectedMetadata == $json;
	$status                = $parsedHeaders['status'];
	$redirectPresent       = $status >= 300 && $status < 400 && isset( $fields['location'] );
	$frontReached          = '1' === ( $fields['x-charter-proof-front-controller-reached'] ?? '' );
	$wordpressVersionMatch = '6.9.5' === ( $fields['x-charter-proof-wordpress-version'] ?? '' );
	$identityMatch         = '' !== $expectedIdentity && $expectedIdentity === $identity;
	$canonicalLocation     = $fields['content-location'] ?? '';
	$cacheControl          = strtolower( $fields['cache-control'] ?? '' );
	$allowOriginMatch      = '*' === ( $fields['access-control-allow-origin'] ?? '' );
	$credentialsPresent    = isset( $fields['access-control-allow-credentials'] );
	$cacheNoStore          = str_contains( $cacheControl, 'no-store' );
	$canonicalLocationMatch = '' !== $canonicalLocation && $requestedUrl === $canonicalLocation;
	$backendReferencePresent = 1 === preg_match( '/\b(?:proxy-origin|fpm|backend)\b/i', $rawHeaders . "\n" . $rawBody );
	$routingEligible       = 'any' === $expectedReachedOption
		|| ( $expectedReached && $frontReached && $wordpressVersionMatch );
	$verificationAccepted  = 200 === $status
	&& 'application/json' === $contentTypeClass
	&& ! $redirectPresent
	&& $identityMatch;
	$verificationAccepted  = $verificationAccepted
		&& $metadataMatch
		&& $allowOriginMatch
		&& ! $credentialsPresent
		&& $cacheNoStore
		&& $canonicalLocationMatch
		&& ! $backendReferencePresent
		&& $routingEligible;

	$result = array(
		'lane'                               => charter_p5_option( $options, 'lane' ),
		'state'                              => charter_p5_option( $options, 'state' ),
		'process_mode'                       => charter_p5_option( $options, 'process-mode' ),
		'requested_url'                      => $requestedUrl,
		'status'                             => $status,
		'status_match'                       => $expectedStatus === $status,
		'content_type_class'                 => $contentTypeClass,
		'body_class'                         => $bodyClass,
		'redirect_present'                   => $redirectPresent,
		'identity_match'                     => $identityMatch,
		'metadata_match'                     => $metadataMatch,
		'access_control_allow_origin'        => $allowOriginMatch ? '*' : 'absent',
		'access_control_credentials_present' => $credentialsPresent,
		'cache_class'                        => $cacheNoStore ? 'no-store' : ( '' === $cacheControl ? 'absent' : 'present' ),
		'canonical_location_match'           => $canonicalLocationMatch,
		'front_controller_reached'           => $frontReached,
		'front_controller_reached_match'     => 'any' === $expectedReachedOption || $expectedReached === $frontReached,
		'wordpress_tree_version_match'       => $wordpressVersionMatch,
		'backend_reference_present'          => $backendReferencePresent,
		'verification_accepted'              => $verificationAccepted,
	);

	$expectsVerification = 200 === $expectedStatus
		&& is_array( $expectedMetadata )
		&& 'false' !== $expectedReachedOption;
	$charterIdentityUnexpected = ( '' === $expectedIdentity && '' !== $identity )
		|| ( 'false' === $expectedReachedOption && $identityMatch )
		|| ( 200 !== $expectedStatus && $identityMatch );

	if (
		! $result['status_match']
		|| ! $result['front_controller_reached_match']
		|| ( $expectedReached && ! $wordpressVersionMatch )
		|| $charterIdentityUnexpected
		|| ( 200 === $expectedStatus && '' !== $expectedIdentity && 'false' !== $expectedReachedOption && ! $identityMatch )
		|| $backendReferencePresent
		|| ( $expectsVerification && ! $verificationAccepted )
		|| ( ! $expectsVerification && $verificationAccepted )
	) {
		charter_p5_fail( 'the response did not match the exact HTTP contract' );
	}

// phpcs:ignore WordPress.WP.AlternativeFunctions.json_encode_json_encode -- Standalone proof tool does not bootstrap WordPress functions.
	$encoded = json_encode( $result, JSON_UNESCAPED_SLASHES );

	if ( ! is_string( $encoded ) ) {
		charter_p5_fail( 'fixed-schema output could not be encoded' );
	}

	// phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_fwrite -- Writes only the fixed-schema sanitized record.
	fwrite( STDOUT, $encoded . PHP_EOL );
}

charter_p5_main();
