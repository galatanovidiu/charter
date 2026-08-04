<?php
/**
 * Validates and canonicalizes disposable Slice 0 P2 runner output.
 *
 * @package GalatanOvidiu\Charter
 */

declare(strict_types=1);

use GalatanOvidiu\Charter\Tests\Fixtures\RestAuthenticationBoundary\FixtureContract;

require_once dirname( __DIR__ ) . '/tests/fixtures/rest-authentication-boundary/FixtureContract.php';

$charter_p2_validator_mode = is_string( $argv[1] ?? null ) ? $argv[1] : '';
$charter_p2_record_type    = match ( $charter_p2_validator_mode ) {
	'process' => FixtureContract::PROCESS_RECORD_TYPE,
	'http'    => FixtureContract::HTTP_RECORD_TYPE,
	default   => '',
};
$charter_p2_failure        = 'http' === $charter_p2_validator_mode
	? FixtureContract::httpFailure()
	: FixtureContract::processFailure();
$charter_p2_input          = stream_get_contents( STDIN );
$charter_p2_input          = false === $charter_p2_input ? '' : $charter_p2_input;
$charter_p2_safe           = '' !== $charter_p2_record_type;
$charter_p2_results        = array();
$charter_p2_contract_lines = array();

$charter_p2_forbidden_patterns = array(
	'/Bearer[ \t]+[A-Za-z0-9\-._~+\/=]{16,}/i',
	'/wordpress_(?:logged_in|sec)_[A-Fa-f0-9]+/',
	'/(?:authorization|cookie|nonce|password)[ \t]*[:=][ \t]*[^\s,}]{8,}/i',
	'/(?<![A-Za-z0-9])[a-f0-9]{48,}(?![A-Za-z0-9])/i',
	'/charter-p2-private-(?:cookie|bearer|authorization)-marker/',
);

foreach ( $charter_p2_forbidden_patterns as $charter_p2_pattern ) {
	if ( 1 === preg_match( $charter_p2_pattern, $charter_p2_input ) ) {
		$charter_p2_safe = false;
	}
}

$charter_p2_lines = preg_split( '/\R/', $charter_p2_input );
foreach ( false === $charter_p2_lines ? array() : $charter_p2_lines as $charter_p2_line ) {
	$charter_p2_line = trim( $charter_p2_line );
	if ( '' === $charter_p2_line ) {
		continue;
	}
	$charter_p2_visible_line = preg_replace( '/\x1B\[[0-?]*[ -\/]*[@-~]/', '', $charter_p2_line );
	$charter_p2_visible_line = is_string( $charter_p2_visible_line ) ? $charter_p2_visible_line : $charter_p2_line;
	if (
		1 === preg_match( "/^ℹ Starting '.+' on the cli container\\.$/u", $charter_p2_visible_line )
		|| 1 === preg_match( "/^✔ Ran `.+` in 'cli'\\. \\(in [0-9]+s [0-9]+ms\\)$/u", $charter_p2_visible_line )
	) {
		continue;
	}
	$charter_p2_contract_lines[] = $charter_p2_line;
	if ( ! str_starts_with( $charter_p2_line, '{' ) || ! str_ends_with( $charter_p2_line, '}' ) ) {
		$charter_p2_safe = false;
		continue;
	}

	try {
		$charter_p2_decoded = json_decode( $charter_p2_line, true, 8, JSON_THROW_ON_ERROR );
	} catch ( Throwable ) {
		$charter_p2_safe = false;
		continue;
	}

	if ( FixtureContract::isResult( $charter_p2_decoded, $charter_p2_record_type ) ) {
		$charter_p2_results[] = $charter_p2_decoded;
	} else {
		$charter_p2_safe = false;
	}
}

$charter_p2_result = $charter_p2_safe && 1 === count( $charter_p2_contract_lines ) && 1 === count( $charter_p2_results )
	? $charter_p2_results[0]
	: $charter_p2_failure;

// phpcs:ignore WordPress.WP.AlternativeFunctions.json_encode_json_encode -- Emits one validated fixed-schema evidence record.
echo json_encode( $charter_p2_result, JSON_THROW_ON_ERROR );
echo "\n";
exit( true === $charter_p2_result['passed'] ? 0 : 1 );
