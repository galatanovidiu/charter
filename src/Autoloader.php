<?php
/**
 * Production class autoloader.
 *
 * @package GalatanOvidiu\Charter
 */

declare(strict_types=1);

namespace GalatanOvidiu\Charter;

/**
 * Loads Charter classes from the production source directory.
 *
 * @since 0.1.0
 */
final class Autoloader {

	private const PREFIX = __NAMESPACE__ . '\\';

	/**
	 * Creates the autoloader.
	 *
	 * @since 0.1.0
	 *
	 * @param string $baseDirectory Absolute path to the namespace root.
	 */
	public function __construct(
		private readonly string $baseDirectory
	) {
	}

	/**
	 * Registers the loader with PHP.
	 *
	 * @since 0.1.0
	 */
	public function register(): void {
		spl_autoload_register( array( $this, 'load' ) );
	}

	/**
	 * Loads a class when it belongs to the Charter namespace.
	 *
	 * @since 0.1.0
	 *
	 * @param string $className Fully qualified class name.
	 */
	public function load( string $className ): void {
		if ( ! str_starts_with( $className, self::PREFIX ) ) {
			return;
		}

		$relativeClass = substr( $className, strlen( self::PREFIX ) );
		$file          = rtrim( $this->baseDirectory, '/\\' )
			. DIRECTORY_SEPARATOR
			. str_replace( '\\', DIRECTORY_SEPARATOR, $relativeClass )
			. '.php';

		if ( is_file( $file ) ) {
			require_once $file;
		}
	}
}
