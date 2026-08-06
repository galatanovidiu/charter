<?php
/**
 * Registers the focused backend client and reveals its one-time test secret.
 *
 * The HTTP runner captures stdout without displaying it and immediately moves
 * the value into a mode-0600 temporary file used by curl.
 *
 * @package GalatanOvidiu\Charter
 */

use GalatanOvidiu\Charter\Plugin;

$charterHttpIdentity = Plugin::boot()->siteState()->identity();
if ( null === $charterHttpIdentity ) {
	throw new RuntimeException( 'The focused HTTP issuer is unavailable.' );
}

$charterHttpSecret = Plugin::boot()->clients()->registerConfidentialClient(
	$charterHttpIdentity->issuer(),
	'charter-http-backend',
	'Charter HTTP backend',
	array( 'https://backend.example.test/callback' ),
	true
);

echo $charterHttpSecret; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- A command substitution captures this test-only secret without rendering or logging it.
