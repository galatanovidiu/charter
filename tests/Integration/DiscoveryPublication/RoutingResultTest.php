<?php
/**
 * Slice 0 discovery path routing tests.
 *
 * @package GalatanOvidiu\Charter
 */

declare(strict_types=1);

namespace GalatanOvidiu\Charter\Tests\Integration\DiscoveryPublication;

use GalatanOvidiu\Charter\Tests\Prototype\DiscoveryPublication\MetadataProjector;
use PHPUnit\Framework\TestCase;

/**
 * Proves that only standards-derived paths select proof metadata.
 *
 * @since 0.1.0
 */
final class RoutingResultTest extends TestCase {

	/**
	 * Verifies the exact root and isolated routes.
	 *
	 * @since 0.1.0
	 */
	public function testRoutesOnlyExactMetadataPaths(): void {
		$issuer   = 'https://issuer.charter.test';
		$resource = $issuer . '/integrations/example';

		self::assertSame(
			MetadataProjector::authorizationServerMetadata( $issuer ),
			MetadataProjector::metadataForPath(
				$issuer,
				array( $resource ),
				'/.well-known/oauth-authorization-server'
			)
		);
		self::assertSame(
			MetadataProjector::protectedResourceMetadata( $issuer, $issuer ),
			MetadataProjector::metadataForPath(
				$issuer,
				array( $resource ),
				'/.well-known/oauth-protected-resource'
			)
		);
		self::assertSame(
			MetadataProjector::protectedResourceMetadata( $issuer, $resource ),
			MetadataProjector::metadataForPath(
				$issuer,
				array( $resource ),
				'/.well-known/oauth-protected-resource/integrations/example'
			)
		);
	}

	/**
	 * Verifies exact non-Charter behavior for substitute paths.
	 *
	 * @since 0.1.0
	 *
	 * @dataProvider substitutePathProvider
	 *
	 * @param string $path The substitute request path.
	 */
	public function testRejectsSubstituteMetadataPaths( string $path ): void {
		self::assertNull(
			MetadataProjector::metadataForPath(
				'https://issuer.charter.test',
				array( 'https://issuer.charter.test/integrations/example' ),
				$path
			)
		);
	}

	/**
	 * Provides rejected substitute paths.
	 *
	 * @since 0.1.0
	 *
	 * @return array<string, array{string}> Paths.
	 */
	public function substitutePathProvider(): array {
		return array(
			'openid configuration'  => array( '/.well-known/openid-configuration' ),
			'wp-json'               => array( '/wp-json/.well-known/oauth-authorization-server' ),
			'path appended'         => array( '/integrations/example/.well-known/oauth-protected-resource' ),
			'duplicate slash'       => array( '//.well-known/oauth-authorization-server' ),
			'encoded isolated path' => array( '/.well-known/oauth-protected-resource/integrations%2Fexample' ),
			'unknown suffix'        => array( '/.well-known/oauth-protected-resource/unknown' ),
			'trailing slash'        => array( '/.well-known/oauth-authorization-server/' ),
		);
	}
}
