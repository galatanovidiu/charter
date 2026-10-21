<?php
/**
 * Trusted reverse-proxy boundary tests.
 *
 * @package GalatanOvidiu\Charter
 */

declare(strict_types=1);

namespace GalatanOvidiu\Charter\Tests\Unit;

use GalatanOvidiu\Charter\Security\TrustedProxyPolicy;
use PHPUnit\Framework\TestCase;

/** Verifies forwarded authority is gated by the immediate network peer. */
final class TrustedProxyPolicyTest extends TestCase {

	/** Untrusted peers cannot redefine either public origin or client source. */
	public function testUntrustedPeerIgnoresForwardedHeaders(): void {
		$policy = new TrustedProxyPolicy( array( '10.0.0.0/8' ) );
		$server = array(
			'REMOTE_ADDR'            => '198.51.100.10',
			'HTTP_HOST'              => 'direct.example.test',
			'HTTP_X_FORWARDED_FOR'   => '203.0.113.25',
			'HTTP_X_FORWARDED_HOST'  => 'public.example.test',
			'HTTP_X_FORWARDED_PROTO' => 'https',
		);

		self::assertSame( '198.51.100.10', $policy->sourceAddress( $server ) );
		self::assertSame( 'http://direct.example.test', $policy->publicOrigin( $server, false ) );
	}

	/** Trusted CIDR peers expose the first untrusted hop and forwarded origin. */
	public function testTrustedPeerAcceptsBoundedForwardingChain(): void {
		$policy = new TrustedProxyPolicy( array( '10.0.0.0/8', '192.0.2.10' ) );
		$server = array(
			'REMOTE_ADDR'            => '10.2.3.4',
			'HTTP_HOST'              => 'internal:8080',
			'HTTP_X_FORWARDED_FOR'   => '203.0.113.25, 192.0.2.10',
			'HTTP_X_FORWARDED_HOST'  => 'public.example.test',
			'HTTP_X_FORWARDED_PROTO' => 'https',
		);

		self::assertSame( '203.0.113.25', $policy->sourceAddress( $server ) );
		self::assertSame( 'https://public.example.test', $policy->publicOrigin( $server, false ) );
	}

	/** IPv4-mapped peers retain distinct IPv4 source buckets and trust matching. */
	public function testIpv4MappedAddressesUseIpv4Semantics(): void {
		$policy = new TrustedProxyPolicy( array( '192.0.2.0/24' ) );
		$server = array(
			'REMOTE_ADDR'          => '::ffff:192.0.2.10',
			'HTTP_HOST'            => 'internal.example.test',
			'HTTP_X_FORWARDED_FOR' => '::ffff:198.51.100.25',
		);

		self::assertTrue( $policy->immediatePeerTrusted( $server ) );
		self::assertSame( '198.51.100.25', $policy->sourceAddress( $server ) );
	}

	/** Oversized attacker prefixes cannot select the trusted proxy's bucket. */
	public function testOversizedForwardingChainUsesBoundedRightmostEntries(): void {
		$policy = new TrustedProxyPolicy( array( '10.0.0.0/8' ) );
		$server = array(
			'REMOTE_ADDR'          => '10.2.3.4',
			'HTTP_HOST'            => 'internal.example.test',
			'HTTP_X_FORWARDED_FOR' => str_repeat( 'invalid,', 600 ) . '203.0.113.25',
		);

		self::assertGreaterThan( 4096, strlen( $server['HTTP_X_FORWARDED_FOR'] ) );
		self::assertSame( '203.0.113.25', $policy->sourceAddress( $server ) );
	}

	/** Invalid configuration and malformed trusted input fail closed. */
	public function testMalformedConfigurationAndHeadersFailClosed(): void {
		$invalid = new TrustedProxyPolicy( array( 'not-a-network' ) );
		$server  = array(
			'REMOTE_ADDR'            => '10.2.3.4',
			'HTTP_HOST'              => 'direct.example.test',
			'HTTP_X_FORWARDED_FOR'   => '203.0.113.25',
			'HTTP_X_FORWARDED_HOST'  => 'public.example.test',
			'HTTP_X_FORWARDED_PROTO' => 'https',
		);

		self::assertFalse( $invalid->configurationValid() );
		self::assertSame( '10.2.3.4', $invalid->sourceAddress( $server ) );
		self::assertNull( $invalid->publicOrigin( $server, false ) );

		$trusted                         = new TrustedProxyPolicy( array( '10.0.0.0/8' ) );
		$server['HTTP_X_FORWARDED_FOR']  = '203.0.113.25, invalid';
		$server['HTTP_X_FORWARDED_HOST'] = 'public.example.test, attacker.example.test';
		self::assertSame( '203.0.113.25', $trusted->sourceAddress( $server ) );
		self::assertNull( $trusted->publicOrigin( $server, false ) );
	}
}
