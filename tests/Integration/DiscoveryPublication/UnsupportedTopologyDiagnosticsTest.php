<?php
/**
 * Slice 0 unsupported-topology diagnostic tests.
 *
 * @package GalatanOvidiu\Charter
 */

declare(strict_types=1);

namespace GalatanOvidiu\Charter\Tests\Integration\DiscoveryPublication;

use GalatanOvidiu\Charter\Tests\Prototype\DiscoveryPublication\UnsupportedTopologyDiagnostics;
use PHPUnit\Framework\TestCase;

/**
 * Proves exact fail-closed path-bearing site diagnostics.
 *
 * @since 0.1.0
 */
final class UnsupportedTopologyDiagnosticsTest extends TestCase {

	/**
	 * Verifies equivalent admin, Site Health, and WP-CLI diagnostics.
	 *
	 * @since 0.1.0
	 */
	public function testPathBearingCanonicalBaseProducesExactDiagnostics(): void {
		$canonicalBase = 'https://path-network.charter.test/team';
		$diagnostics   = UnsupportedTopologyDiagnostics::forCanonicalBase( $canonicalBase );

		self::assertFalse( $diagnostics['supported'] );
		self::assertTrue( $diagnostics['plugin_active'] );
		self::assertFalse( $diagnostics['fatal'] );
		self::assertSame( 'unsupported_path_topology', $diagnostics['reason_code'] );
		self::assertStringContainsString( $canonicalBase, $diagnostics['message'] );
		self::assertStringContainsString( 'bare origin', $diagnostics['message'] );
		self::assertStringContainsString( 'notice-error', $diagnostics['administrator_notice'] );
		self::assertStringNotContainsString( 'is-dismissible', $diagnostics['administrator_notice'] );
		self::assertSame( 'critical', $diagnostics['site_health']['status'] );
		self::assertSame( $diagnostics['message'], $diagnostics['site_health']['description'] );
		self::assertSame( $diagnostics['message'], $diagnostics['wp_cli']['message'] );
		self::assertSame( 1, $diagnostics['wp_cli']['exit_code'] );
	}

	/**
	 * Verifies that an exact bare-origin identity has no error diagnostics.
	 *
	 * @since 0.1.0
	 */
	public function testBareOriginHasNoUnsupportedTopologyDiagnostics(): void {
		$diagnostics = UnsupportedTopologyDiagnostics::forCanonicalBase( 'https://issuer.charter.test' );

		self::assertTrue( $diagnostics['supported'] );
		self::assertTrue( $diagnostics['plugin_active'] );
		self::assertFalse( $diagnostics['fatal'] );
		self::assertNull( $diagnostics['reason_code'] );
		self::assertSame( '', $diagnostics['message'] );
		self::assertSame( '', $diagnostics['administrator_notice'] );
		self::assertSame( array(), $diagnostics['site_health'] );
		self::assertSame( array(), $diagnostics['wp_cli'] );
	}
}
