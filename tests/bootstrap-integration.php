<?php
/**
 * WordPress integration test bootstrap.
 *
 * @package GalatanOvidiu\Charter
 */

declare(strict_types=1);

define( 'CHARTER_TEST_ROOT', dirname( __DIR__ ) );

require CHARTER_TEST_ROOT . '/vendor/autoload.php';

$charter_tests_directory = getenv( 'WP_TESTS_DIR' );

if ( false === $charter_tests_directory || '' === $charter_tests_directory ) {
	$charter_tests_directory = '/wordpress-phpunit';
}

require_once $charter_tests_directory . '/includes/functions.php';

tests_add_filter(
	'muplugins_loaded',
	static function (): void {
		require_once CHARTER_TEST_ROOT . '/charter.php';
	}
);

require $charter_tests_directory . '/includes/bootstrap.php';
