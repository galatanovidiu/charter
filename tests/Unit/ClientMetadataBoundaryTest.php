<?php
/**
 * Client ID Metadata Document boundary unit tests.
 *
 * @package GalatanOvidiu\Charter
 */

declare(strict_types=1);

namespace GalatanOvidiu\Charter\Tests\Unit;

use GalatanOvidiu\Charter\OAuth\ClientMetadataFreshness;
use GalatanOvidiu\Charter\OAuth\ClientMetadataIdentifier;
use GalatanOvidiu\Charter\OAuth\ClientMetadataResolutionException;
use GalatanOvidiu\Charter\Security\BoundedHostResolver;
use GalatanOvidiu\Charter\Security\GlobalAddressPolicy;
use InvalidArgumentException;
use PHPUnit\Framework\TestCase;

/** Exercises pure URL, DNS, address, and cache-policy boundaries. */
final class ClientMetadataBoundaryTest extends TestCase {

	/** Verifies the exact accepted HTTPS URL profile without normalization. */
	public function testIdentifierPreservesExactSafeClientId(): void {
		$implicit = ClientMetadataIdentifier::fromString( 'https://client.example/metadata.json' );
		$explicit = ClientMetadataIdentifier::fromString( 'https://client.example:443/metadata.json' );

		self::assertSame( 'https://client.example/metadata.json', $implicit->exact() );
		self::assertSame( 'client.example', $implicit->host() );
		self::assertSame( 'https://client.example:443/metadata.json', $explicit->exact() );
		self::assertNotSame( $implicit->exact(), $explicit->exact() );
	}

	/**
	 * Verifies unsafe or ambiguous Client Identifier URL forms fail closed.
	 *
	 * @dataProvider invalidIdentifierProvider
	 *
	 * @param string $identifier Rejected identifier.
	 */
	public function testIdentifierRejectsUnsafeOrAmbiguousForms( string $identifier ): void {
		$this->expectException( InvalidArgumentException::class );

		ClientMetadataIdentifier::fromString( $identifier );
	}

	/**
	 * Returns representative rejected Client Identifier URL forms.
	 *
	 * @return iterable<string, array{0: string}>
	 */
	public function invalidIdentifierProvider(): iterable {
		yield 'plain HTTP' => array( 'http://client.example/metadata.json' );
		yield 'root path' => array( 'https://client.example/' );
		yield 'missing path' => array( 'https://client.example' );
		yield 'query' => array( 'https://client.example/metadata.json?v=1' );
		yield 'userinfo' => array( 'https://user@client.example/metadata.json' );
		yield 'non-effective port' => array( 'https://client.example:444/metadata.json' );
		yield 'address literal' => array( 'https://127.0.0.1/metadata.json' );
		yield 'numeric spelling' => array( 'https://0x7f000001/metadata.json' );
		yield 'encoded dot segment' => array( 'https://client.example/safe/%252e%252e/metadata.json' );
		yield 'unicode host' => array( 'https://cliënt.example/metadata.json' );
	}

	/** Verifies conservative special-use rejection and global-unicast acceptance. */
	public function testGlobalAddressPolicyRejectsEveryUnsafeFamily(): void {
		foreach ( array( '0.0.0.0', '10.0.0.1', '127.0.0.1', '169.254.1.1', '192.168.1.1', '224.0.0.1', '::1', '::ffff:8.8.8.8', 'fc00::1', 'fe80::1', 'ff02::1' ) as $address ) {
			self::assertFalse( GlobalAddressPolicy::isGloballyUsable( $address ), $address );
		}
		foreach ( array( '1.1.1.1', '8.8.8.8', '2001:4860:4860::8888', '2606:4700:4700::1111' ) as $address ) {
			self::assertTrue( GlobalAddressPolicy::isGloballyUsable( $address ), $address );
		}
	}

	/** Verifies complete A and AAAA collection rejects a mixed unsafe answer set. */
	public function testResolverScreensTheCompleteTerminalAnswerSet(): void {
		$resolver = new BoundedHostResolver(
			static function ( string $name, string $type, int $remainingMilliseconds ): array {
				unset( $remainingMilliseconds );
				$records = 'A' === $type
					? array(
						array(
							'type'  => 'A',
							'name'  => $name,
							'value' => '8.8.8.8',
						),
					)
					: array(
						array(
							'type'  => 'AAAA',
							'name'  => $name,
							'value' => 'fe80::1',
						),
					);

				return array(
					array(
						'status'     => 'NOERROR',
						'truncated'  => false,
						'malformed'  => false,
						'wire_bytes' => 100,
						'records'    => $records,
					),
				);
			}
		);

		try {
			$resolver->resolve( 'client.example' );
			self::fail( 'The mixed terminal answer set was accepted.' );
		} catch ( ClientMetadataResolutionException $exception ) {
			self::assertSame( 'dns_unsafe_address', $exception->classification() );
		}
	}

	/** Verifies the one-hour cap, fallback, and mandatory-refetch directives. */
	public function testFreshnessPolicyIsBoundedAndNeverStoresNoCacheResponses(): void {
		$capped = ClientMetadataFreshness::evaluate( array( 'cache-control' => array( 'max-age=7200' ) ), 100, 105, 105 );
		self::assertTrue( $capped->reusable() );
		self::assertSame( 3705, $capped->freshUntil() );

		$fallback = ClientMetadataFreshness::evaluate( array(), 100, 105, 105 );
		self::assertTrue( $fallback->reusable() );
		self::assertSame( 405, $fallback->freshUntil() );

		foreach ( array( 'no-store', 'no-cache' ) as $directive ) {
			$policy = ClientMetadataFreshness::evaluate( array( 'cache-control' => array( $directive ) ), 100, 105, 105 );
			self::assertFalse( $policy->reusable() );
			self::assertSame( 105, $policy->freshUntil() );
		}
	}
}
