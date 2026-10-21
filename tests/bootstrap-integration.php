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

$charter_tests_config = '/tmp/charter-wp-tests-config.php';
if ( ! defined( 'WP_TESTS_CONFIG_FILE_PATH' ) && is_readable( $charter_tests_config ) ) {
	// phpcs:ignore WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedConstantFound -- WordPress PHPUnit bootstrap contract.
	define( 'WP_TESTS_CONFIG_FILE_PATH', $charter_tests_config );
}

require_once $charter_tests_directory . '/includes/functions.php';

tests_add_filter(
	'muplugins_loaded',
	static function (): void {
		if ( ! defined( 'CHARTER_DEVELOPMENT_MODE' ) ) {
			define( 'CHARTER_DEVELOPMENT_MODE', true );
		}
		if ( ! defined( 'CHARTER_DEVELOPMENT_HOSTS' ) ) {
			define( 'CHARTER_DEVELOPMENT_HOSTS', array( 'example.org' ) );
		}
		if ( '1' !== getenv( 'CHARTER_SKIP_PRODUCTION_PLUGIN' ) ) {
			if ( is_multisite() ) {
				$networkPlugins = get_site_option( 'active_sitewide_plugins', array() );
				$networkPlugins[ plugin_basename( CHARTER_TEST_ROOT . '/charter.php' ) ] = time();
				update_site_option( 'active_sitewide_plugins', $networkPlugins );
			}
			require_once CHARTER_TEST_ROOT . '/charter.php';
		}
	}
);

require $charter_tests_directory . '/includes/bootstrap.php';
