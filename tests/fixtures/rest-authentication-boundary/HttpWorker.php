<?php
/**
 * Real-HTTP front controller for the disposable Slice 0 P2 proof.
 *
 * This file is reached through the already-running disposable wp-env web
 * container. It registers proof-only routes for one request and delegates final
 * response projection to WordPress's real REST server.
 *
 * @package GalatanOvidiu\Charter
 */

declare(strict_types=1);

namespace GalatanOvidiu\Charter\Tests\Fixtures\RestAuthenticationBoundary;

use GalatanOvidiu\Charter\Tests\Prototype\RestAuthenticationBoundary\RestAuthenticationBoundary;
use GalatanOvidiu\Charter\Tests\Prototype\RestAuthenticationBoundary\SyntheticBearerFixtures;
use RuntimeException;
use Throwable;

// phpcs:ignore WordPress.PHP.IniSet.display_errors_Disallowed -- The HTTP proof worker must keep diagnostics off the wire.
ini_set( 'display_errors', '0' );
// phpcs:ignore WordPress.PHP.IniSet.log_errors_Disallowed -- The HTTP proof worker must not persist authentication detail.
ini_set( 'log_errors', '0' );
ob_start();

$charter_p2_http_boundary = null;

try {
	if ( ! defined( 'REST_REQUEST' ) ) {
		// phpcs:ignore WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedConstantFound -- Core owns this exact request-mode constant.
		define( 'REST_REQUEST', true );
	}

	require_once '/var/www/html/wp-load.php';
	require_once dirname( __DIR__, 3 ) . '/vendor/autoload.php';
	require_once __DIR__ . '/ProofRoutes.php';

	while ( 0 < ob_get_level() ) {
		ob_end_clean();
	}

	$charter_p2_http_user_a             = filter_var( $_SERVER['HTTP_X_CHARTER_P2_USER_A'] ?? null, FILTER_VALIDATE_INT );
	$charter_p2_http_user_b             = filter_var( $_SERVER['HTTP_X_CHARTER_P2_USER_B'] ?? null, FILTER_VALIDATE_INT );
	$charter_p2_http_case               = is_string( $_SERVER['HTTP_X_CHARTER_P2_CASE'] ?? null ) ? $_SERVER['HTTP_X_CHARTER_P2_CASE'] : 'none';
	$charter_p2_http_fixture_credential = is_string( $_SERVER['HTTP_X_CHARTER_P2_FIXTURE_CREDENTIAL'] ?? null ) ? $_SERVER['HTTP_X_CHARTER_P2_FIXTURE_CREDENTIAL'] : '';
	// phpcs:ignore WordPress.Security.NonceVerification.Recommended -- Read-only proof route selection occurs before REST authentication.
	$charter_p2_http_route = is_string( $_GET['p2_route'] ?? null ) ? $_GET['p2_route'] : '';
	// phpcs:ignore WordPress.Security.NonceVerification.Recommended -- Read-only proof boundary selection is fixed by the local runner.
	$charter_p2_http_boundary_mode = is_string( $_GET['p2_boundary'] ?? null ) ? $_GET['p2_boundary'] : 'proof';

	if (
		! is_int( $charter_p2_http_user_a )
		|| ! is_int( $charter_p2_http_user_b )
		|| 1 > $charter_p2_http_user_a
		|| 1 > $charter_p2_http_user_b
		|| ! in_array( $charter_p2_http_case, array( 'none', 'valid', 'invalid', 'insufficient' ), true )
		|| 1 !== preg_match( '/^[a-f0-9]{64}$/D', $charter_p2_http_fixture_credential )
		|| ! in_array( $charter_p2_http_route, array( 'public', 'protected', 'denied', 'multi' ), true )
		|| ! in_array( $charter_p2_http_boundary_mode, array( 'core', 'proof' ), true )
	) {
		throw new RuntimeException( 'Invalid proof request.' );
	}

	unset( $_GET['p2_route'], $_GET['p2_boundary'], $_REQUEST['p2_route'], $_REQUEST['p2_boundary'] );

	$charter_p2_http_cases     = array(
		'valid'        => SyntheticBearerFixtures::CASE_VALID_A_DEFAULT,
		'invalid'      => SyntheticBearerFixtures::CASE_UNKNOWN,
		'insufficient' => SyntheticBearerFixtures::CASE_INSUFFICIENT_SCOPE,
	);
	$charter_p2_http_overrides = isset( $charter_p2_http_cases[ $charter_p2_http_case ] )
		? array( $charter_p2_http_cases[ $charter_p2_http_case ] => $charter_p2_http_fixture_credential )
		: array();
	$charter_p2_http_fixtures  = new SyntheticBearerFixtures( $charter_p2_http_user_a, $charter_p2_http_user_b, $charter_p2_http_overrides );

	$charter_p2_http_boundary = RestAuthenticationBoundary::fromFixtures( $charter_p2_http_fixtures );
	$charter_p2_http_routes   = new ProofRoutes( $charter_p2_http_boundary );
	$charter_p2_http_server   = rest_get_server();

	$charter_p2_http_routes->register( $charter_p2_http_server );
	if ( 'proof' === $charter_p2_http_boundary_mode ) {
		$charter_p2_http_boundary->install();
	}

	$charter_p2_http_paths = array(
		'public'    => ProofRoutes::PUBLIC_ROUTE,
		'protected' => ProofRoutes::PROTECTED_ROUTE,
		'denied'    => ProofRoutes::DENIED_ROUTE,
		'multi'     => ProofRoutes::MULTI_ROUTE,
	);

	ob_start();
	$charter_p2_http_server->serve_request( $charter_p2_http_paths[ $charter_p2_http_route ] );
	$charter_p2_http_body = ob_get_clean();

	if ( ! is_string( $charter_p2_http_body ) ) {
		throw new RuntimeException( 'REST response was unavailable.' );
	}

	json_decode( $charter_p2_http_body, true, 16, JSON_THROW_ON_ERROR );
	$charter_p2_http_boundary->remove();
	$charter_p2_http_boundary = null;

	echo $charter_p2_http_body; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- Re-emits WordPress's already encoded REST response.
} catch ( Throwable ) {
	if ( $charter_p2_http_boundary instanceof RestAuthenticationBoundary ) {
		$charter_p2_http_boundary->remove();
	}

	while ( 0 < ob_get_level() ) {
		ob_end_clean();
	}

	header_remove( 'WWW-Authenticate' );
	header( 'Content-Type: application/json; charset=UTF-8', true, 500 );
	echo '{"code":"proof_worker_failed","data":{"status":500}}';
}
