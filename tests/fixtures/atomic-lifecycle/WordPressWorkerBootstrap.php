<?php
/**
 * Exact WordPress bootstrap for each disposable Slice 0 P1 worker.
 *
 * @package GalatanOvidiu\Charter
 */

declare(strict_types=1);

namespace GalatanOvidiu\Charter\Tests\Fixtures\AtomicLifecycle;

// phpcs:disable WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedConstantFound -- Exact Core bootstrap constants are required in this standalone process.

use RuntimeException;

/**
 * Loads the supported WordPress Core before opening the proof connection.
 */
final class WordPressWorkerBootstrap {

	/**
	 * Loads the exact short WordPress bootstrap for one worker process.
	 *
	 * @param LaneConfiguration $lane Disposable lane configuration.
	 * @throws RuntimeException When the exact Core boundary cannot be loaded.
	 */
	public static function load( LaneConfiguration $lane ): void {
		$wordpressDirectory = rtrim( $lane->wordpressSourceDirectory(), '/' ) . '/';
		$settingsFile       = $wordpressDirectory . 'wp-settings.php';
		$dropInFile         = $wordpressDirectory . 'wp-content/db.php';

		if ( ! is_file( $settingsFile ) || is_file( $dropInFile ) ) {
			throw new RuntimeException( 'Exact WordPress worker source was unavailable or contained a database drop-in.' );
		}

		self::defineConstant( 'ABSPATH', $wordpressDirectory );
		self::defineConstant( 'SHORTINIT', true );
		self::defineConstant( 'DB_HOST', self::databaseHost() );
		self::defineConstant( 'DB_NAME', self::requiredEnvironment( 'CHARTER_ATOMIC_DB_NAME' ) );
		self::defineConstant( 'DB_USER', self::requiredEnvironment( 'CHARTER_ATOMIC_DB_USER' ) );
		self::defineConstant( 'DB_PASSWORD', self::requiredEnvironment( 'CHARTER_ATOMIC_DB_PASSWORD' ) );
		self::defineConstant( 'DB_CHARSET', 'utf8mb4' );
		self::defineConstant( 'DB_COLLATE', '' );
		self::defineConstant( 'WP_DEBUG', false );
		self::defineConstant( 'WP_DEBUG_DISPLAY', false );
		self::defineConstant( 'WP_DEBUG_LOG', false );

		global $table_prefix, $wpdb, $wp_version;
		// phpcs:ignore WordPress.WP.GlobalVariablesOverride.Prohibited -- Required input to the exact standalone Core bootstrap.
		$table_prefix = 'wp_';
		require $settingsFile;

		if (
			HarnessContract::WORDPRESS_VERSION !== $wp_version
			|| ! $wpdb instanceof \wpdb
			|| ! function_exists( 'wp_start_object_cache' )
			|| is_file( $dropInFile )
		) {
			throw new RuntimeException( 'Exact WordPress worker bootstrap failed.' );
		}
	}

	/**
	 * Returns the private host and port in Core's DB_HOST format.
	 */
	private static function databaseHost(): string {
		$host = self::requiredEnvironment( 'CHARTER_ATOMIC_DB_HOST' );
		$port = self::requiredEnvironment( 'CHARTER_ATOMIC_DB_PORT' );

		return $host . ':' . $port;
	}

	/**
	 * Returns one required private worker environment value.
	 *
	 * @param string $name Fixed environment key.
	 * @throws RuntimeException When the private value is unavailable.
	 */
	private static function requiredEnvironment( string $name ): string {
		$value = getenv( $name );

		if ( false === $value || '' === $value ) {
			throw new RuntimeException( 'Private WordPress worker configuration was unavailable.' );
		}

		return $value;
	}

	/**
	 * Defines one exact Core bootstrap constant once.
	 *
	 * @param string      $name Fixed Core constant name.
	 * @param bool|string $value Fixed or private configuration value.
	 * @throws RuntimeException When a Core constant was already defined.
	 */
	private static function defineConstant( string $name, bool|string $value ): void {
		// phpcs:ignore WordPress.NamingConventions.PrefixAllGlobals.VariableConstantNameFound -- Defines only the fixed Core constants passed above.
		if ( defined( $name ) || ! define( $name, $value ) ) {
			throw new RuntimeException( 'WordPress worker constant could not be defined.' );
		}
	}
}
