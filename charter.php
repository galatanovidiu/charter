<?php
/**
 * Plugin Name:       Charter – OAuth 2.1 Authorization Server
 * Description:       Provides a secure, standards-compliant OAuth 2.1 authorization server for WordPress.
 * Version:           0.1.0
 * Requires at least: 6.9
 * Requires PHP:      8.4
 * Author:            Ovidiu Galatan
 * Author URI:        https://github.com/galatanovidiu
 * License:           GPL-2.0-or-later
 * License URI:       https://www.gnu.org/licenses/gpl-2.0.html
 * Text Domain:       charter
 * Domain Path:       /languages
 *
 * @package GalatanOvidiu\Charter
 */

declare(strict_types=1);

namespace GalatanOvidiu\Charter;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

define( 'CHARTER_VERSION', '0.1.0' );
define( 'CHARTER_FILE', __FILE__ );
define( 'CHARTER_PATH', __DIR__ . '/' );

require_once CHARTER_PATH . 'src/Autoloader.php';

$charter_autoloader = new Autoloader( CHARTER_PATH . 'src' );
$charter_autoloader->register();

Plugin::boot();
