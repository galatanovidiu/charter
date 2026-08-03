<?php
/**
 * Slice 0 Multisite harness integration tests.
 *
 * @package GalatanOvidiu\Charter
 */

declare(strict_types=1);

namespace GalatanOvidiu\Charter\Tests\Integration\Multisite;

use WP_UnitTestCase;

/**
 * Verifies the observable WordPress environment used by the Slice 0 proof.
 *
 * @since 0.1.0
 */
final class MultisiteHarnessTest extends WP_UnitTestCase {

	/**
	 * Verifies that the Slice 0 integration harness boots Multisite.
	 *
	 * @since 0.1.0
	 */
	public function testWordPressTestHarnessUsesMultisite(): void {
		self::assertTrue( is_multisite() );
	}

	/**
	 * Verifies that the Slice 0 integration harness uses WordPress 6.9.
	 *
	 * @since 0.1.0
	 */
	public function testWordPressTestHarnessUsesWordPress69(): void {
		self::assertMatchesRegularExpression( '/^6\\.9\\.[0-9]+$/D', get_bloginfo( 'version' ) );
	}
}
