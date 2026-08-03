<?php
/**
 * Autoloader unit tests.
 *
 * @package GalatanOvidiu\Charter
 */

declare(strict_types=1);

namespace GalatanOvidiu\Charter\Tests\Unit;

use GalatanOvidiu\Charter\Autoloader;
use GalatanOvidiu\Charter\Plugin;
use PHPUnit\Framework\TestCase;

/**
 * Tests the first-party production autoloader.
 *
 * @since 0.1.0
 */
final class AutoloaderTest extends TestCase {

	/**
	 * Verifies that the production namespace maps to the source directory.
	 *
	 * @since 0.1.0
	 *
	 * @runInSeparateProcess
	 * @preserveGlobalState disabled
	 */
	public function testProductionAutoloaderLoadsPluginClass(): void {
		self::assertFalse( class_exists( Plugin::class, false ) );

		$autoloader = new Autoloader( dirname( __DIR__, 2 ) . '/src' );
		$autoloader->load( Plugin::class );

		self::assertTrue( class_exists( Plugin::class, false ) );
	}
}
