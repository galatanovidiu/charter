<?php
/**
 * Exact interrupted-run cleanup for the disposable Slice 0 P2 runners.
 *
 * Run through `wp eval-file`; output is captured by the owning shell runner.
 *
 * @package GalatanOvidiu\Charter
 */

declare(strict_types=1);

namespace GalatanOvidiu\Charter\Tests\Fixtures\RestAuthenticationBoundary;

use Throwable;

require_once __DIR__ . '/OwnedProofUsers.php';

$charter_p2_cleanup_args = isset( $args ) && is_array( $args ) ? $args : array();
$charter_p2_cleanup_run  = is_string( $charter_p2_cleanup_args[0] ?? null ) ? $charter_p2_cleanup_args[0] : '';
$charter_p2_cleanup_ok   = false;

try {
	$charter_p2_cleanup_ok = OwnedProofUsers::cleanupRun( $charter_p2_cleanup_run );
} catch ( Throwable ) {
	$charter_p2_cleanup_ok = false;
}

// phpcs:ignore WordPress.WP.AlternativeFunctions.json_encode_json_encode -- Emits one captured boolean-only cleanup result.
echo json_encode( array( 'cleanup_complete' => $charter_p2_cleanup_ok ), JSON_THROW_ON_ERROR );
echo "\n";
