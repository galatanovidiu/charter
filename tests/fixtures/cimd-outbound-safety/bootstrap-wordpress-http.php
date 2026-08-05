<?php
/**
 * Boots exact WordPress Core HTTP without a database or production plugin.
 *
 * @package GalatanOvidiu\Charter
 */

declare(strict_types=1);

// Exact proof bootstrap intentionally defines Core's expected global constants.
// phpcs:disable WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedConstantFound
// phpcs:disable WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedFunctionFound

$charter_p3_project_root = dirname( __DIR__, 3 );
define( 'CHARTER_TEST_ROOT', $charter_p3_project_root );
require $charter_p3_project_root . '/vendor/autoload.php';

define( 'ABSPATH', '/usr/src/wordpress/' );
define( 'WPINC', 'wp-includes' );
define( 'WP_DEBUG', false );
define( 'WP_CONTENT_DIR', '/tmp/charter-p3-content' );
define( 'MINUTE_IN_SECONDS', 60 );
define( 'HOUR_IN_SECONDS', 3600 );

require ABSPATH . WPINC . '/version.php';
if ( ! isset( $wp_version ) || '6.9.5' !== $wp_version ) {
	throw new RuntimeException( 'P3 WordPress HTTP bootstrap rejected the Core version.' );
}

require ABSPATH . WPINC . '/plugin.php';
require ABSPATH . WPINC . '/class-wp-error.php';
require ABSPATH . WPINC . '/load.php';

if ( ! function_exists( 'absint' ) ) {
	/**
	 * Returns the absolute integer form used by Core HTTP response projection.
	 *
	 * @param mixed $maybeint Candidate integer.
	 * @return int Absolute integer.
	 */
	function absint( $maybeint ): int {
		return abs( (int) $maybeint );
	}
}

require ABSPATH . WPINC . '/functions.php';
require ABSPATH . WPINC . '/formatting.php';
require ABSPATH . WPINC . '/kses.php';
require ABSPATH . WPINC . '/http.php';
require ABSPATH . WPINC . '/class-wp-http-response.php';
require ABSPATH . WPINC . '/class-wp-http-requests-response.php';
require ABSPATH . WPINC . '/class-wp-http-proxy.php';
require ABSPATH . WPINC . '/class-wp-http-cookie.php';
require ABSPATH . WPINC . '/class-wp-http-encoding.php';
require ABSPATH . WPINC . '/Requests/src/Autoload.php';
WpOrg\Requests\Autoload::register();
require ABSPATH . WPINC . '/class-wp-http-requests-hooks.php';
require ABSPATH . WPINC . '/class-wp-http.php';

if ( '2.0.11' !== WpOrg\Requests\Requests::VERSION ) {
	throw new RuntimeException( 'P3 WordPress HTTP bootstrap rejected the Requests version.' );
}

if ( ! function_exists( '__' ) ) {
	/**
	 * Returns untranslated fixed proof text.
	 *
	 * @param string $text Fixed Core message.
	 * @return string Unchanged message.
	 */
	function __( $text ): string {
		return (string) $text;
	}
}

if ( ! function_exists( 'get_bloginfo' ) ) {
	/**
	 * Returns a non-site-bearing fixed proof value for Core HTTP defaults.
	 *
	 * @param string $show Requested field.
	 * @return string Fixed proof value.
	 */
	function get_bloginfo( $show = '' ): string {
		return 'version' === $show ? '6.9.5' : 'proof-unavailable';
	}
}

if ( ! function_exists( 'get_option' ) ) {
	/**
	 * Returns only the non-site-bearing options needed by the Core HTTP path.
	 *
	 * @param string $option  Requested option name.
	 * @param mixed  $default_value Caller default.
	 * @return mixed Fixed filtered proof value or caller default.
	 */
	function get_option( $option, $default_value = false ): mixed {
		// phpcs:ignore WordPress.NamingConventions.PrefixAllGlobals.DynamicHooknameFound,WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedHooknameFound -- Reproduces Core's exact option pre-filter in the DB-free proof stub.
		$filtered = apply_filters( 'pre_option_' . $option, false, $option, $default_value );
		if ( false !== $filtered ) {
			return $filtered;
		}

		return in_array( $option, array( 'home', 'siteurl' ), true )
			? 'https://proof-unavailable.invalid'
			: $default_value;
	}
}

add_filter(
	'pre_option_home',
	static function (): string {
		return 'https://proof-unavailable.invalid';
	}
);

define( 'CHARTER_P3_WORDPRESS_HTTP_BOOTSTRAPPED', true );
