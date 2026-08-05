<?php
/**
 * Slice 0 CIMD address-policy tests.
 *
 * @package GalatanOvidiu\Charter
 */

declare(strict_types=1);

namespace GalatanOvidiu\Charter\Tests\Integration\CimdOutboundSafety;

use GalatanOvidiu\Charter\Tests\Prototype\CimdOutboundSafety\AddressPolicy;
use InvalidArgumentException;
use PHPUnit\Framework\TestCase;

/**
 * Proves complete special-purpose and non-unicast address rejection.
 *
 * @since 0.1.0
 */
final class AddressPolicyTest extends TestCase {

	/**
	 * Verifies the first and last address of every current IANA IPv4 row.
	 *
	 * @since 0.1.0
	 *
	 * @dataProvider specialIpv4BoundaryProvider
	 *
	 * @param string $address Special-purpose address.
	 */
	public function testRejectsEveryCurrentIanaIpv4SpecialPurposeBoundary( string $address ): void {
		self::assertFalse( AddressPolicy::isGloballyUsable( $address ) );
	}

	/**
	 * Verifies the first and last address of every current IANA IPv6 row.
	 *
	 * @since 0.1.0
	 *
	 * @dataProvider specialIpv6BoundaryProvider
	 *
	 * @param string $address Special-purpose address.
	 */
	public function testRejectsEveryCurrentIanaIpv6SpecialPurposeBoundary( string $address ): void {
		self::assertFalse( AddressPolicy::isGloballyUsable( $address ) );
	}

	/**
	 * Verifies globally usable addresses immediately outside bounded registry ranges.
	 *
	 * @since 0.1.0
	 *
	 * @dataProvider adjacentGloballyUsableProvider
	 *
	 * @param string $address Globally usable adjacent address.
	 */
	public function testAcceptsAdjacentGloballyUsableAddresses( string $address ): void {
		self::assertTrue( AddressPolicy::isGloballyUsable( $address ) );
	}

	/**
	 * Verifies that mapped IPv4 cannot evade either address family policy.
	 *
	 * @since 0.1.0
	 *
	 * @dataProvider ipv4MappedIpv6Provider
	 *
	 * @param string $address IPv4-mapped IPv6 address.
	 */
	public function testRejectsIpv4MappedIpv6Addresses( string $address ): void {
		self::assertFalse( AddressPolicy::isGloballyUsable( $address ) );
	}

	/**
	 * Verifies IPv6 addresses outside IANA's allocated 2000::/3 global-unicast
	 * space are rejected even when they are not in a narrower registry row.
	 *
	 * @dataProvider unallocatedIpv6Provider
	 *
	 * @param string $address Unallocated or deprecated IPv6 address.
	 */
	public function testRejectsIpv6OutsideAllocatedGlobalUnicastSpace( string $address ): void {
		self::assertFalse( AddressPolicy::isGloballyUsable( $address ) );
	}

	/**
	 * Verifies that one unsafe or malformed answer rejects the complete set.
	 *
	 * @since 0.1.0
	 *
	 * @dataProvider rejectedAnswerSetProvider
	 *
	 * @param array $addresses Complete terminal answer set.
	 */
	public function testRejectsTheCompleteSetWhenAnyAnswerIsUnsafe( array $addresses ): void {
		$this->expectException( InvalidArgumentException::class );

		AddressPolicy::assertGloballyUsableSet( $addresses );
	}

	/**
	 * Verifies canonical binary deduplication without changing the first spelling.
	 *
	 * @since 0.1.0
	 */
	public function testReturnsOnlyUniqueGloballyUsableAnswers(): void {
		self::assertSame(
			array(
				'8.8.8.8',
				'2001:4860:4860::8888',
			),
			AddressPolicy::assertGloballyUsableSet(
				array(
					'8.8.8.8',
					'8.8.8.8',
					'2001:4860:4860::8888',
					'2001:4860:4860:0:0:0:0:8888',
				)
			)
		);
	}

	/**
	 * Provides the boundaries of every IPv4 registry row current on 2026-08-05.
	 *
	 * @since 0.1.0
	 *
	 * @return iterable<string, array{string}> Special-purpose boundaries.
	 */
	public function specialIpv4BoundaryProvider(): iterable {
		$blocks = array(
			array( '0.0.0.0/8', '0.0.0.0', '0.255.255.255' ),
			array( '0.0.0.0/32', '0.0.0.0', '0.0.0.0' ),
			array( '10.0.0.0/8', '10.0.0.0', '10.255.255.255' ),
			array( '100.64.0.0/10', '100.64.0.0', '100.127.255.255' ),
			array( '127.0.0.0/8', '127.0.0.0', '127.255.255.255' ),
			array( '169.254.0.0/16', '169.254.0.0', '169.254.255.255' ),
			array( '172.16.0.0/12', '172.16.0.0', '172.31.255.255' ),
			array( '192.0.0.0/24', '192.0.0.0', '192.0.0.255' ),
			array( '192.0.0.0/29', '192.0.0.0', '192.0.0.7' ),
			array( '192.0.0.8/32', '192.0.0.8', '192.0.0.8' ),
			array( '192.0.0.9/32', '192.0.0.9', '192.0.0.9' ),
			array( '192.0.0.10/32', '192.0.0.10', '192.0.0.10' ),
			array( '192.0.0.170/32', '192.0.0.170', '192.0.0.170' ),
			array( '192.0.0.171/32', '192.0.0.171', '192.0.0.171' ),
			array( '192.0.2.0/24', '192.0.2.0', '192.0.2.255' ),
			array( '192.31.196.0/24', '192.31.196.0', '192.31.196.255' ),
			array( '192.52.193.0/24', '192.52.193.0', '192.52.193.255' ),
			array( '192.88.99.0/24', '192.88.99.0', '192.88.99.255' ),
			array( '192.88.99.2/32', '192.88.99.2', '192.88.99.2' ),
			array( '192.168.0.0/16', '192.168.0.0', '192.168.255.255' ),
			array( '192.175.48.0/24', '192.175.48.0', '192.175.48.255' ),
			array( '198.18.0.0/15', '198.18.0.0', '198.19.255.255' ),
			array( '198.51.100.0/24', '198.51.100.0', '198.51.100.255' ),
			array( '203.0.113.0/24', '203.0.113.0', '203.0.113.255' ),
			array( '240.0.0.0/4', '240.0.0.0', '255.255.255.255' ),
			array( '255.255.255.255/32', '255.255.255.255', '255.255.255.255' ),
		);

		foreach ( $blocks as $block ) {
			yield $block[0] . ' first' => array( $block[1] );
			yield $block[0] . ' last' => array( $block[2] );
		}

		yield 'IPv4 multicast first' => array( '224.0.0.0' );
		yield 'IPv4 multicast last' => array( '239.255.255.255' );
	}

	/**
	 * Provides the boundaries of every IPv6 registry row current on 2026-08-05.
	 *
	 * @since 0.1.0
	 *
	 * @return iterable<string, array{string}> Special-purpose boundaries.
	 */
	public function specialIpv6BoundaryProvider(): iterable {
		$blocks = array(
			array( '::1/128', '::1', '::1' ),
			array( '::/128', '::', '::' ),
			array( '::ffff:0:0/96', '::ffff:0:0', '::ffff:ffff:ffff' ),
			array( '64:ff9b::/96', '64:ff9b::', '64:ff9b::ffff:ffff' ),
			array( '64:ff9b:1::/48', '64:ff9b:1::', '64:ff9b:1:ffff:ffff:ffff:ffff:ffff' ),
			array( '100::/64', '100::', '100::ffff:ffff:ffff:ffff' ),
			array( '100:0:0:1::/64', '100:0:0:1::', '100:0:0:1:ffff:ffff:ffff:ffff' ),
			array( '2001::/23', '2001::', '2001:1ff:ffff:ffff:ffff:ffff:ffff:ffff' ),
			array( '2001::/32', '2001::', '2001:0:ffff:ffff:ffff:ffff:ffff:ffff' ),
			array( '2001:1::1/128', '2001:1::1', '2001:1::1' ),
			array( '2001:1::2/128', '2001:1::2', '2001:1::2' ),
			array( '2001:1::3/128', '2001:1::3', '2001:1::3' ),
			array( '2001:2::/48', '2001:2::', '2001:2:0:ffff:ffff:ffff:ffff:ffff' ),
			array( '2001:3::/32', '2001:3::', '2001:3:ffff:ffff:ffff:ffff:ffff:ffff' ),
			array( '2001:4:112::/48', '2001:4:112::', '2001:4:112:ffff:ffff:ffff:ffff:ffff' ),
			array( '2001:10::/28', '2001:10::', '2001:1f:ffff:ffff:ffff:ffff:ffff:ffff' ),
			array( '2001:20::/28', '2001:20::', '2001:2f:ffff:ffff:ffff:ffff:ffff:ffff' ),
			array( '2001:30::/28', '2001:30::', '2001:3f:ffff:ffff:ffff:ffff:ffff:ffff' ),
			array( '2001:db8::/32', '2001:db8::', '2001:db8:ffff:ffff:ffff:ffff:ffff:ffff' ),
			array( '2002::/16', '2002::', '2002:ffff:ffff:ffff:ffff:ffff:ffff:ffff' ),
			array( '2620:4f:8000::/48', '2620:4f:8000::', '2620:4f:8000:ffff:ffff:ffff:ffff:ffff' ),
			array( '3fff::/20', '3fff::', '3fff:fff:ffff:ffff:ffff:ffff:ffff:ffff' ),
			array( '5f00::/16', '5f00::', '5f00:ffff:ffff:ffff:ffff:ffff:ffff:ffff' ),
			array( 'fc00::/7', 'fc00::', 'fdff:ffff:ffff:ffff:ffff:ffff:ffff:ffff' ),
			array( 'fe80::/10', 'fe80::', 'febf:ffff:ffff:ffff:ffff:ffff:ffff:ffff' ),
		);

		foreach ( $blocks as $block ) {
			yield $block[0] . ' first' => array( $block[1] );
			yield $block[0] . ' last' => array( $block[2] );
		}

		yield 'IPv6 multicast first' => array( 'ff00::' );
		yield 'IPv6 multicast last' => array( 'ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff' );
	}

	/**
	 * Provides accepted neighbors outside special-purpose ranges.
	 *
	 * @since 0.1.0
	 *
	 * @return iterable<string, array{string}> Globally usable addresses.
	 */
	public function adjacentGloballyUsableProvider(): iterable {
		$addresses = array(
			'after 0/8'              => '1.0.0.0',
			'before private 10/8'    => '9.255.255.255',
			'after private 10/8'     => '11.0.0.0',
			'before shared space'    => '100.63.255.255',
			'after shared space'     => '100.128.0.0',
			'before loopback'        => '126.255.255.255',
			'after loopback'         => '128.0.0.0',
			'before link local'      => '169.253.255.255',
			'after link local'       => '169.255.0.0',
			'before private 172/12'  => '172.15.255.255',
			'after private 172/12'   => '172.32.0.0',
			'before protocol block'  => '191.255.255.255',
			'after protocol block'   => '192.0.1.0',
			'before TEST-NET-1'      => '192.0.1.255',
			'after TEST-NET-1'       => '192.0.3.0',
			'before AS112-v4'        => '192.31.195.255',
			'after AS112-v4'         => '192.31.197.0',
			'before AMT'             => '192.52.192.255',
			'after AMT'              => '192.52.194.0',
			'before deprecated 6to4' => '192.88.98.255',
			'after deprecated 6to4'  => '192.88.100.0',
			'before private 192/16'  => '192.167.255.255',
			'after private 192/16'   => '192.169.0.0',
			'before AS112 service'   => '192.175.47.255',
			'after AS112 service'    => '192.175.49.0',
			'before benchmarking'    => '198.17.255.255',
			'after benchmarking'     => '198.20.0.0',
			'before TEST-NET-2'      => '198.51.99.255',
			'after TEST-NET-2'       => '198.51.101.0',
			'before TEST-NET-3'      => '203.0.112.255',
			'after TEST-NET-3'       => '203.0.114.0',
			'before IPv6 IETF /23'   => '2000:ffff:ffff:ffff:ffff:ffff:ffff:ffff',
			'after IPv6 IETF /23'    => '2001:200::',
			'before IPv6 docs'       => '2001:db7:ffff:ffff:ffff:ffff:ffff:ffff',
			'after IPv6 docs'        => '2001:db9::',
			'before IPv6 6to4'       => '2001:ffff:ffff:ffff:ffff:ffff:ffff:ffff',
			'after IPv6 6to4'        => '2003::',
			'before IPv6 AS112'      => '2620:4f:7fff:ffff:ffff:ffff:ffff:ffff',
			'after IPv6 AS112'       => '2620:4f:8001::',
			'before IPv6 docs /20'   => '3ffe:ffff:ffff:ffff:ffff:ffff:ffff:ffff',
			'after IPv6 docs /20'    => '3fff:1000::',
		);

		foreach ( $addresses as $name => $address ) {
			yield $name => array( $address );
		}
	}

	/**
	 * Provides representative non-global IPv6 spellings outside 2000::/3.
	 *
	 * @return iterable<string, array{string}> Non-global addresses.
	 */
	public function unallocatedIpv6Provider(): iterable {
		yield 'IPv4-compatible style' => array( '::8.8.8.8' );
		yield 'below allocated global unicast' => array( '1fff:ffff:ffff:ffff:ffff:ffff:ffff:ffff' );
		yield 'above allocated global unicast' => array( '4000::1' );
		yield 'unallocated 5f01 space' => array( '5f01::1' );
		yield 'unallocated below SRv6 space' => array( '5eff:ffff:ffff:ffff:ffff:ffff:ffff:ffff' );
		yield 'deprecated site-local' => array( 'fec0::1' );
	}

	/**
	 * Provides mapped IPv4 spellings that must never be accepted.
	 *
	 * @since 0.1.0
	 *
	 * @return iterable<string, array{string}> Mapped addresses.
	 */
	public function ipv4MappedIpv6Provider(): iterable {
		yield 'mapped globally usable IPv4' => array( '::ffff:8.8.8.8' );
		yield 'mapped private IPv4' => array( '::ffff:10.0.0.1' );
		yield 'mapped loopback IPv4' => array( '::ffff:127.0.0.1' );
		yield 'mapped hexadecimal form' => array( '::ffff:0808:0808' );
	}

	/**
	 * Provides sets that must be rejected as a whole.
	 *
	 * @since 0.1.0
	 *
	 * @return iterable<string, array{list<string>}> Rejected sets.
	 */
	public function rejectedAnswerSetProvider(): iterable {
		yield 'empty' => array( array() );
		yield 'mixed IPv4' => array( array( '8.8.8.8', '10.0.0.1' ) );
		yield 'mixed IPv6' => array( array( '2001:4860:4860::8888', 'fe80::1' ) );
		yield 'mixed families' => array( array( '8.8.8.8', '2001:db8::1' ) );
		yield 'invalid IPv4' => array( array( '999.0.0.1' ) );
		yield 'invalid IPv6' => array( array( '2001:::1' ) );
		yield 'zone identifier' => array( array( 'fe80::1%en0' ) );
		yield 'leading whitespace' => array( array( ' 8.8.8.8' ) );
		yield 'trailing whitespace' => array( array( '8.8.8.8 ' ) );
	}
}
