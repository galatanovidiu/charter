<?php
/**
 * Plugin unit tests.
 *
 * @package GalatanOvidiu\Charter
 */

declare(strict_types=1);

namespace GalatanOvidiu\Charter\Tests\Unit;

use GalatanOvidiu\Charter\Plugin;
use PHPUnit\Framework\TestCase;

/**
 * Tests the plugin composition root.
 *
 * @since 0.1.0
 */
final class PluginTest extends TestCase {

	/**
	 * Verifies that the plugin boots only once.
	 *
	 * @since 0.1.0
	 */
	public function testBootIsIdempotent(): void {
		self::assertSame( Plugin::boot(), Plugin::boot() );
	}
}
