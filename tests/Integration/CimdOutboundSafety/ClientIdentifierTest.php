<?php
/**
 * Slice 0 CIMD Client Identifier tests.
 *
 * @package GalatanOvidiu\Charter
 */

declare(strict_types=1);

namespace GalatanOvidiu\Charter\Tests\Integration\CimdOutboundSafety;

use GalatanOvidiu\Charter\Tests\Prototype\CimdOutboundSafety\ClientIdentifier;
use InvalidArgumentException;
use PHPUnit\Framework\TestCase;

/**
 * Proves the exact, unnormalized CIMD Client Identifier boundary.
 *
 * @since 0.1.0
 */
final class ClientIdentifierTest extends TestCase {

	/**
	 * Verifies that parsing never replaces the submitted security identity.
	 *
	 * @since 0.1.0
	 *
	 * @dataProvider validIdentifierProvider
	 *
	 * @param string $submitted    Submitted Client Identifier.
	 * @param string $expectedHost Parsed DNS host.
	 */
	public function testPreservesTheExactSubmittedIdentity( string $submitted, string $expectedHost ): void {
		$identifier = ClientIdentifier::fromString( $submitted );

		self::assertSame( $submitted, $identifier->exact() );
		self::assertSame( $submitted, $identifier->fetchUrl() );
		self::assertSame( $submitted, $identifier->cacheKey() );
		self::assertSame( $expectedHost, $identifier->host() );
		self::assertSame( 443, $identifier->effectivePort() );
	}

	/**
	 * Verifies that an explicit default port remains a distinct identity.
	 *
	 * @since 0.1.0
	 */
	public function testExplicitPort443RemainsDistinctFromAnElidedPort(): void {
		$elided   = ClientIdentifier::fromString( 'https://client.example/metadata' );
		$explicit = ClientIdentifier::fromString( 'https://client.example:443/metadata' );

		self::assertNotSame( $elided->exact(), $explicit->exact() );
		self::assertNotSame( $elided->cacheKey(), $explicit->cacheKey() );
		self::assertSame( 443, $elided->effectivePort() );
		self::assertSame( 443, $explicit->effectivePort() );
	}

	/**
	 * Verifies rejection before DNS for every disallowed URL class.
	 *
	 * @since 0.1.0
	 *
	 * @dataProvider invalidIdentifierProvider
	 *
	 * @param string $submitted Invalid Client Identifier.
	 */
	public function testRejectsUnsafeOrAmbiguousIdentifiersBeforeUse( string $submitted ): void {
		$this->expectException( InvalidArgumentException::class );

		ClientIdentifier::fromString( $submitted );
	}

	/**
	 * Provides accepted exact identities.
	 *
	 * @since 0.1.0
	 *
	 * @return array<string, array{string, string}> Accepted identities.
	 */
	public function validIdentifierProvider(): array {
		return array(
			'ordinary path'              => array( 'https://client.example/metadata', 'client.example' ),
			'explicit port 443'          => array( 'https://client.example:443/metadata', 'client.example' ),
			'case preserved'             => array( 'HTTPS://Client.Example/Metadata', 'Client.Example' ),
			'percent encoding preserved' => array( 'https://client.example/%63imd', 'client.example' ),
			'punycode host preserved'    => array( 'https://xn--bcher-kva.example/metadata', 'xn--bcher-kva.example' ),
		);
	}

	/**
	 * Provides rejected Client Identifier URL classes.
	 *
	 * @since 0.1.0
	 *
	 * @return array<string, array{string}> Rejected identities.
	 */
	public function invalidIdentifierProvider(): array {
		$longLabel = str_repeat( 'a', 64 ) . '.example';

		return array(
			'http scheme'              => array( 'http://client.example/metadata' ),
			'non-443 port'             => array( 'https://client.example:8443/metadata' ),
			'no path'                  => array( 'https://client.example' ),
			'root path only'           => array( 'https://client.example/' ),
			'userinfo'                 => array( 'https://user@client.example/metadata' ),
			'query'                    => array( 'https://client.example/metadata?tenant=one' ),
			'fragment'                 => array( 'https://client.example/metadata#one' ),
			'literal dot segment'      => array( 'https://client.example/a/./metadata' ),
			'literal dot-dot segment'  => array( 'https://client.example/a/../metadata' ),
			'encoded dot segment'      => array( 'https://client.example/a/%2e/metadata' ),
			'encoded dot-dot segment'  => array( 'https://client.example/a/%2E%2E/metadata' ),
			'invalid percent encoding' => array( 'https://client.example/%zz' ),
			'backslash ambiguity'      => array( 'https://client.example\\@other.example/metadata' ),
			'control character'        => array( "https://client.example/meta\ndata" ),
			'raw unicode host'         => array( 'https://bücher.example/metadata' ),
			'ipv4 literal'             => array( 'https://192.0.2.1/metadata' ),
			'ipv6 literal'             => array( 'https://[2001:db8::1]/metadata' ),
			'decimal IPv4 integer'     => array( 'https://2130706433/metadata' ),
			'octal IPv4 integer'       => array( 'https://017700000001/metadata' ),
			'hexadecimal IPv4 integer' => array( 'https://0x7f000001/metadata' ),
			'octal dotted IPv4'        => array( 'https://0177.0.0.1/metadata' ),
			'hexadecimal dotted IPv4'  => array( 'https://0x7f.0x0.0x0.0x1/metadata' ),
			'four-times encoded dot'   => array( 'https://client.example/a/%2525252e/metadata' ),
			'four-times encoded dots'  => array( 'https://client.example/a/%2525252e%2525252e/metadata' ),
			'label over 63 bytes'      => array( 'https://' . $longLabel . '/metadata' ),
			'URL over 2048 bytes'      => array( 'https://client.example/' . str_repeat( 'a', 2026 ) ),
		);
	}
}
