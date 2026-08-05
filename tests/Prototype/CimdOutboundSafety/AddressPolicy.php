<?php
/**
 * Disposable Slice 0 CIMD address policy.
 *
 * @package GalatanOvidiu\Charter
 */

declare(strict_types=1);

namespace GalatanOvidiu\Charter\Tests\Prototype\CimdOutboundSafety;

use InvalidArgumentException;

/**
 * Screens complete resolver answer sets against pinned special-purpose ranges.
 *
 * @since 0.1.0
 */
final class AddressPolicy {

	/**
	 * Current IANA IPv4 special-purpose rows plus multicast.
	 *
	 * Overlapping rows are retained so the proof fixture remains reviewable
	 * against the registry snapshot pinned on 2026-08-05.
	 *
	 * @var list<string>
	 */
	private const SPECIAL_IPV4_BLOCKS = array(
		'0.0.0.0/8',
		'0.0.0.0/32',
		'10.0.0.0/8',
		'100.64.0.0/10',
		'127.0.0.0/8',
		'169.254.0.0/16',
		'172.16.0.0/12',
		'192.0.0.0/24',
		'192.0.0.0/29',
		'192.0.0.8/32',
		'192.0.0.9/32',
		'192.0.0.10/32',
		'192.0.0.170/32',
		'192.0.0.171/32',
		'192.0.2.0/24',
		'192.31.196.0/24',
		'192.52.193.0/24',
		'192.88.99.0/24',
		'192.88.99.2/32',
		'192.168.0.0/16',
		'192.175.48.0/24',
		'198.18.0.0/15',
		'198.51.100.0/24',
		'203.0.113.0/24',
		'224.0.0.0/4',
		'240.0.0.0/4',
		'255.255.255.255/32',
	);

	/**
	 * Current IANA IPv6 special-purpose rows plus multicast.
	 *
	 * @var list<string>
	 */
	private const SPECIAL_IPV6_BLOCKS = array(
		'::1/128',
		'::/128',
		'::ffff:0:0/96',
		'64:ff9b::/96',
		'64:ff9b:1::/48',
		'100::/64',
		'100:0:0:1::/64',
		'2001::/23',
		'2001::/32',
		'2001:1::1/128',
		'2001:1::2/128',
		'2001:1::3/128',
		'2001:2::/48',
		'2001:3::/32',
		'2001:4:112::/48',
		'2001:10::/28',
		'2001:20::/28',
		'2001:30::/28',
		'2001:db8::/32',
		'2002::/16',
		'2620:4f:8000::/48',
		'3fff::/20',
		'5f00::/16',
		'fc00::/7',
		'fe80::/10',
		'ff00::/8',
	);

	/**
	 * Reports whether one exact textual IP is outside every rejected block.
	 *
	 * @since 0.1.0
	 *
	 * @param string $address Exact resolver answer.
	 */
	public static function isGloballyUsable( string $address ): bool {
		$packed = inet_pton( $address );

		if ( false === $packed ) {
			return false;
		}

		if ( 16 === strlen( $packed ) && ! self::contains( $packed, '2000::/3' ) ) {
			return false;
		}

		$blocks = 4 === strlen( $packed ) ? self::SPECIAL_IPV4_BLOCKS : self::SPECIAL_IPV6_BLOCKS;

		foreach ( $blocks as $block ) {
			if ( self::contains( $packed, $block ) ) {
				return false;
			}
		}

		return true;
	}

	/**
	 * Requires every terminal answer to be globally usable.
	 *
	 * Binary-equivalent answers are returned once while retaining the first
	 * textual spelling supplied by the resolver.
	 *
	 * @since 0.1.0
	 *
	 * @param array<mixed> $addresses Complete terminal A and AAAA answer set.
	 * @return list<string> Binary-unique globally usable answers.
	 * @throws InvalidArgumentException When the set is empty, malformed, or unsafe.
	 */
	public static function assertGloballyUsableSet( array $addresses ): array {
		if ( array() === $addresses ) {
			throw new InvalidArgumentException( 'The resolver answer set must not be empty.' );
		}

		$unique = array();

		foreach ( $addresses as $address ) {
			if ( ! is_string( $address ) || ! self::isGloballyUsable( $address ) ) {
				throw new InvalidArgumentException( 'Every resolver answer must be a globally usable IP address.' );
			}

			$packed = inet_pton( $address );
			if ( false === $packed ) {
				throw new InvalidArgumentException( 'Every resolver answer must be a valid IP address.' );
			}

			$key = strlen( $packed ) . ':' . bin2hex( $packed );
			if ( ! isset( $unique[ $key ] ) ) {
				$unique[ $key ] = $address;
			}
		}

		return array_values( $unique );
	}

	/**
	 * Tests one packed address against a fixed CIDR block.
	 *
	 * @param string $packedAddress Binary resolver answer.
	 * @param string $block         Fixed CIDR block.
	 */
	private static function contains( string $packedAddress, string $block ): bool {
		list( $network, $prefixText ) = explode( '/', $block, 2 );
		$packedNetwork                = inet_pton( $network );
		$prefix                       = (int) $prefixText;

		if ( false === $packedNetwork || strlen( $packedAddress ) !== strlen( $packedNetwork ) ) {
			return false;
		}

		$wholeBytes = intdiv( $prefix, 8 );
		if ( substr( $packedAddress, 0, $wholeBytes ) !== substr( $packedNetwork, 0, $wholeBytes ) ) {
			return false;
		}

		$remainingBits = $prefix % 8;
		if ( 0 === $remainingBits ) {
			return true;
		}

		$mask = ( 0xff << ( 8 - $remainingBits ) ) & 0xff;

		return ( ord( $packedAddress[ $wholeBytes ] ) & $mask ) === ( ord( $packedNetwork[ $wholeBytes ] ) & $mask );
	}
}
