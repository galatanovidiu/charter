<?php
/**
 * Disposable Slice 0 discovery publication HTTP front controller.
 *
 * @package GalatanOvidiu\Charter
 */

declare(strict_types=1);

use GalatanOvidiu\Charter\Tests\Prototype\DiscoveryPublication\MetadataProjector;

require '/workspace/vendor/autoload.php';

( static function (): void {
	$wp_version = null; // phpcs:ignore WordPress.WP.GlobalVariablesOverride.Prohibited -- Reads the exact pinned WordPress version file in function scope.
	require '/var/www/html/wordpress/wp-includes/version.php';

	if ( '6.9.5' !== $wp_version ) {
		http_response_code( 500 );
		header( 'Content-Type: text/plain; charset=UTF-8' );
		echo 'Pinned WordPress source mismatch.';
		return;
	}

	$issuer = (string) getenv( 'P5_ISSUER' );
	// phpcs:ignore WordPress.WP.AlternativeFunctions.file_get_contents_file_get_contents -- Reads a fixed proof-owned state file.
	$state = trim( (string) file_get_contents( '/state/current' ) );
	// phpcs:ignore WordPress.WP.AlternativeFunctions.parse_url_parse_url -- Disposable worker does not bootstrap WordPress functions.
	$authority = (string) parse_url( $issuer, PHP_URL_HOST );
	// phpcs:ignore WordPress.WP.AlternativeFunctions.parse_url_parse_url -- Disposable worker does not bootstrap WordPress functions.
	$issuerPort = parse_url( $issuer, PHP_URL_PORT );

	if ( is_int( $issuerPort ) ) {
		$authority .= ':' . $issuerPort;
	}

	$requestHost = strtolower( (string) ( $_SERVER['HTTP_HOST'] ?? '' ) );
	$requestUri  = (string) ( $_SERVER['REQUEST_URI'] ?? '' );
	// phpcs:ignore WordPress.WP.AlternativeFunctions.parse_url_parse_url -- Disposable worker does not bootstrap WordPress functions.
	$path = (string) parse_url( $requestUri, PHP_URL_PATH );
	// phpcs:ignore WordPress.WP.AlternativeFunctions.parse_url_parse_url -- Disposable worker does not bootstrap WordPress functions.
	$query    = parse_url( $requestUri, PHP_URL_QUERY );
	$resource = $issuer . '/integrations/example';

	header( 'X-Charter-Proof-Front-Controller-Reached: 1' );
	header( 'X-Charter-Proof-WordPress-Version: 6.9.5' );

	if ( strtolower( $authority ) !== $requestHost ) {
		http_response_code( 404 );
		header( 'Content-Type: text/plain; charset=UTF-8' );
		echo 'Non-Charter host mapping.';
		return;
	}

	if ( null !== $query ) {
		http_response_code( 404 );
		header( 'Content-Type: text/plain; charset=UTF-8' );
		echo 'Non-Charter query request.';
		return;
	}

	if ( 'available' === $state ) {
		http_response_code( 404 );
		header( 'Content-Type: text/plain; charset=UTF-8' );
		echo 'Non-Charter available site.';
		return;
	}

	if ( '/charter-proof/operation' === $path ) {
		header( 'Content-Type: application/json; charset=UTF-8' );
		header( 'Access-Control-Allow-Origin: *' );
		header( 'Cache-Control: no-store' );

		if ( 'enabled' !== $state ) {
			http_response_code( 403 );
			// phpcs:ignore WordPress.WP.AlternativeFunctions.json_encode_json_encode -- Disposable worker does not bootstrap WordPress functions.
			echo json_encode( array( 'error' => 'issuer_not_enabled' ), JSON_UNESCAPED_SLASHES );
			return;
		}

		http_response_code( 200 );
		// phpcs:ignore WordPress.WP.AlternativeFunctions.json_encode_json_encode -- Disposable worker does not bootstrap WordPress functions.
		echo json_encode(
			array(
				'issuer' => $issuer,
				'state'  => 'enabled',
			),
			JSON_UNESCAPED_SLASHES
		);
		return;
	}

	try {
		$metadata = MetadataProjector::metadataForPath( $issuer, array( $resource ), $path );
	} catch ( InvalidArgumentException $exception ) {
		unset( $exception );
		$metadata = null;
	}

	if ( null === $metadata ) {
		http_response_code( 404 );
		header( 'Content-Type: text/plain; charset=UTF-8' );
		echo 'Non-Charter request path.';
		return;
	}

	http_response_code( 200 );
	header( 'Content-Type: application/json; charset=UTF-8' );
	header( 'Access-Control-Allow-Origin: *' );
	header( 'Cache-Control: no-store' );
	header( 'Content-Location: ' . $issuer . $path );
// phpcs:ignore WordPress.WP.AlternativeFunctions.json_encode_json_encode -- Disposable worker does not bootstrap WordPress functions.
	echo json_encode( $metadata, JSON_UNESCAPED_SLASHES );
} )();
