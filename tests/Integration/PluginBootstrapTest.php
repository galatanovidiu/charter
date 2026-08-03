<?php
/**
 * Plugin bootstrap integration tests.
 *
 * @package GalatanOvidiu\Charter
 */

declare(strict_types=1);

namespace GalatanOvidiu\Charter\Tests\Integration;

use GalatanOvidiu\Charter\Plugin;
use WP_UnitTestCase;

/**
 * Verifies that Charter loads in WordPress.
 *
 * @since 0.1.0
 */
final class PluginBootstrapTest extends WP_UnitTestCase {

	/**
	 * Verifies the plugin's version and composition root.
	 *
	 * @since 0.1.0
	 */
	public function testPluginBootsInWordPress(): void {
		$pluginMetadata = get_file_data(
			CHARTER_FILE,
			array(
				'Version'    => 'Version',
				'RequiresWP' => 'Requires at least',
			),
			'plugin'
		);

		self::assertSame( $pluginMetadata['Version'], CHARTER_VERSION );
		self::assertSame( '6.9', $pluginMetadata['RequiresWP'] );
		self::assertSame( CHARTER_TEST_ROOT . '/charter.php', CHARTER_FILE );
		self::assertSame( Plugin::boot(), Plugin::boot() );
	}
}
