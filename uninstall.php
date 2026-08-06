<?php
/**
 * Charter uninstall entry point.
 *
 * @package GalatanOvidiu\Charter
 */

declare(strict_types=1);

namespace GalatanOvidiu\Charter;

if ( ! defined( 'WP_UNINSTALL_PLUGIN' ) ) {
	exit;
}

require_once __DIR__ . '/src/Autoloader.php';

$charter_uninstall_autoloader = new Autoloader( __DIR__ . '/src' );
$charter_uninstall_autoloader->register();

Uninstaller::uninstall();
