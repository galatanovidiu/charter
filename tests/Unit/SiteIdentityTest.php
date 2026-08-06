<?php
/**
 * Canonical site identity unit tests.
 *
 * @package GalatanOvidiu\Charter
 */

declare(strict_types=1);

namespace GalatanOvidiu\Charter\Tests\Unit;

use GalatanOvidiu\Charter\Site\SiteIdentity;
use InvalidArgumentException;
use PHPUnit\Framework\TestCase;

/**
 * Tests the bare-origin identity boundary without WordPress state.
 *
 * @since 0.1.0
 */
final class SiteIdentityTest extends TestCase {

	/**
	 * Verifies deterministic bare-origin normalization.
	 *
	 * @since 0.1.0
	 */
	public function testNormalizesOneCanonicalBareOrigin(): void {
		$identity = SiteIdentity::fromUrl( 'HTTPS://Example.COM:443/' );

		self::assertSame( 'https://example.com', $identity->issuer() );
	}

	/**
	 * Verifies that path-addressed and insecure production issuers fail closed.
	 *
	 * @since 0.1.0
	 *
	 * @dataProvider unsupportedIssuerProvider
	 *
	 * @param string $issuer Unsupported issuer.
	 */
	public function testRejectsUnsupportedIssuerTopologies( string $issuer ): void {
		$this->expectException( InvalidArgumentException::class );

		SiteIdentity::fromUrl( $issuer );
	}

	/**
	 * Returns unsupported issuer cases.
	 *
	 * @since 0.1.0
	 *
	 * @return array<string, array{string}> Cases.
	 */
	public function unsupportedIssuerProvider(): array {
		return array(
			'path'       => array( 'https://example.com/team' ),
			'query'      => array( 'https://example.com?issuer=other' ),
			'userinfo'   => array( 'https://user@example.com' ),
			'plain http' => array( 'http://example.com' ),
		);
	}

	/**
	 * Verifies explicit local-development HTTP host policy.
	 *
	 * @since 0.1.0
	 */
	public function testAllowsOnlyExplicitDevelopmentHttpHosts(): void {
		self::assertSame( 'http://localhost:8890', SiteIdentity::fromUrl( 'http://localhost:8890/', true )->issuer() );
		self::assertSame( 'http://dev.example', SiteIdentity::fromUrl( 'http://dev.example', true, array( 'dev.example' ) )->issuer() );

		$this->expectException( InvalidArgumentException::class );
		SiteIdentity::fromUrl( 'http://unlisted.example', true, array( 'dev.example' ) );
	}
}
