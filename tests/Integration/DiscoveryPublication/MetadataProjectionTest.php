<?php
/**
 * Slice 0 discovery metadata projection tests.
 *
 * @package GalatanOvidiu\Charter
 */

declare(strict_types=1);

namespace GalatanOvidiu\Charter\Tests\Integration\DiscoveryPublication;

use GalatanOvidiu\Charter\Tests\Prototype\DiscoveryPublication\MetadataProjector;
use InvalidArgumentException;
use PHPUnit\Framework\TestCase;

/**
 * Proves exact RFC 8414 and RFC 9728 proof projections.
 *
 * @since 0.1.0
 */
final class MetadataProjectionTest extends TestCase {

	/**
	 * Verifies the exact authorization-server projection fixed by the P5 plan.
	 *
	 * @since 0.1.0
	 */
	public function testProjectsExactAuthorizationServerMetadata(): void {
		$issuer = 'https://issuer.charter.test';

		self::assertSame(
			array(
				'issuer'                                => $issuer,
				'authorization_endpoint'                => $issuer . '/charter-proof/authorize',
				'token_endpoint'                        => $issuer . '/charter-proof/token',
				'registration_endpoint'                 => $issuer . '/charter-proof/register',
				'revocation_endpoint'                   => $issuer . '/charter-proof/revoke',
				'response_types_supported'              => array( 'code' ),
				'response_modes_supported'              => array( 'query' ),
				'grant_types_supported'                 => array( 'authorization_code', 'refresh_token' ),
				'token_endpoint_auth_methods_supported' => array( 'none', 'client_secret_post' ),
				'revocation_endpoint_auth_methods_supported' => array( 'none', 'client_secret_post' ),
				'code_challenge_methods_supported'      => array( 'S256' ),
				'scopes_supported'                      => array( 'wordpress:access', 'offline_access' ),
			),
			MetadataProjector::authorizationServerMetadata( $issuer )
		);
		self::assertSame(
			$issuer . '/.well-known/oauth-authorization-server',
			MetadataProjector::authorizationServerUrl( $issuer )
		);
	}

	/**
	 * Verifies root and path-specific protected-resource derivation.
	 *
	 * @since 0.1.0
	 */
	public function testProjectsRootAndIsolatedProtectedResourceMetadata(): void {
		$issuer           = 'https://issuer.charter.test';
		$isolatedResource = $issuer . '/integrations/example';

		self::assertSame(
			array(
				'resource'              => $issuer,
				'authorization_servers' => array( $issuer ),
			),
			MetadataProjector::protectedResourceMetadata( $issuer, $issuer )
		);
		self::assertSame(
			$issuer . '/.well-known/oauth-protected-resource',
			MetadataProjector::protectedResourceUrl( $issuer, $issuer )
		);
		self::assertSame(
			array(
				'resource'              => $isolatedResource,
				'authorization_servers' => array( $issuer ),
			),
			MetadataProjector::protectedResourceMetadata( $issuer, $isolatedResource )
		);
		self::assertSame(
			$issuer . '/.well-known/oauth-protected-resource/integrations/example',
			MetadataProjector::protectedResourceUrl( $issuer, $isolatedResource )
		);
	}

	/**
	 * Verifies a separately established non-default-port identity without normalization.
	 *
	 * @since 0.1.0
	 */
	public function testPreservesAnExactNonDefaultPortIdentity(): void {
		$issuer = 'https://issuer.charter.test:8443';

		self::assertSame(
			$issuer . '/.well-known/oauth-authorization-server',
			MetadataProjector::authorizationServerUrl( $issuer )
		);
		self::assertSame(
			$issuer . '/.well-known/oauth-protected-resource',
			MetadataProjector::protectedResourceUrl( $issuer, $issuer )
		);
		self::assertSame( $issuer, MetadataProjector::authorizationServerMetadata( $issuer )['issuer'] );
	}

	/**
	 * Verifies that request-shaped or unsupported identities are rejected.
	 *
	 * @since 0.1.0
	 *
	 * @dataProvider invalidIdentityProvider
	 *
	 * @param string $issuer            The candidate issuer.
	 * @param string $protectedResource The candidate resource.
	 */
	public function testRejectsUnsupportedIssuerOrResource( string $issuer, string $protectedResource ): void {
		$this->expectException( InvalidArgumentException::class );

		MetadataProjector::protectedResourceUrl( $issuer, $protectedResource );
	}

	/**
	 * Provides unsupported identity combinations.
	 *
	 * @since 0.1.0
	 *
	 * @return array<string, array{string, string}> Invalid candidates.
	 */
	public function invalidIdentityProvider(): array {
		return array(
			'path-bearing site issuer' => array( 'https://issuer.charter.test/team', 'https://issuer.charter.test/team' ),
			'issuer query'             => array( 'https://issuer.charter.test?tenant=one', 'https://issuer.charter.test' ),
			'issuer fragment'          => array( 'https://issuer.charter.test#one', 'https://issuer.charter.test' ),
			'issuer user info'         => array( 'https://user@issuer.charter.test', 'https://issuer.charter.test' ),
			'issuer wrong scheme'      => array( 'http://issuer.charter.test', 'http://issuer.charter.test' ),
			'issuer invalid port zero' => array( 'https://issuer.charter.test:0', 'https://issuer.charter.test:0' ),
			'issuer port too large'    => array( 'https://issuer.charter.test:65536', 'https://issuer.charter.test:65536' ),
			'foreign resource'         => array( 'https://issuer.charter.test', 'https://other.charter.test/integrations/example' ),
			'resource query'           => array( 'https://issuer.charter.test', 'https://issuer.charter.test/integrations/example?one=two' ),
			'resource fragment'        => array( 'https://issuer.charter.test', 'https://issuer.charter.test/integrations/example#one' ),
		);
	}
}
