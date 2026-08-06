<?php
/**
 * Outbound global-address policy.
 *
 * @package GalatanOvidiu\Charter
 */

declare(strict_types=1);

namespace GalatanOvidiu\Charter\Security;

/** Rejects current IANA special-purpose, multicast, private, and non-unicast ranges. */
final class GlobalAddressPolicy {

	private const IPV4_BLOCKS = array(
		'0.0.0.0/8',
		'10.0.0.0/8',
		'100.64.0.0/10',
		'127.0.0.0/8',
		'169.254.0.0/16',
		'172.16.0.0/12',
		'192.0.0.0/24',
		'192.0.2.0/24',
		'192.31.196.0/24',
		'192.52.193.0/24',
		'192.88.99.0/24',
		'192.168.0.0/16',
		'192.175.48.0/24',
		'198.18.0.0/15',
		'198.51.100.0/24',
		'203.0.113.0/24',
		'224.0.0.0/4',
		'240.0.0.0/4',
		'255.255.255.255/32',
	);

	private const IPV6_BLOCKS = array(
		'::/128',
		'::1/128',
		'::ffff:0:0/96',
		'64:ff9b::/96',
		'64:ff9b:1::/48',
		'100::/64',
		'100:0:0:1::/64',
		'2001::/23',
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
	 * Reports whether an exact IP address is globally usable unicast.
	 *
	 * @param string $address Candidate IP address.
	 */
	public static function isGloballyUsable( string $address ): bool {
		$packed = inet_pton( $address );
		if ( false === $packed ) {
			return false;
		}
		if ( 16 === strlen( $packed ) && ! self::contains( $packed, '2000::/3' ) ) {
			return false;
		}

		foreach ( 4 === strlen( $packed ) ? self::IPV4_BLOCKS : self::IPV6_BLOCKS as $block ) {
			if ( self::contains( $packed, $block ) ) {
				return false;
			}
		}

		return true;
	}

	/**
	 * Reports whether packed address bytes belong to one CIDR block.
	 *
	 * @param string $address Packed address bytes.
	 * @param string $block Exact CIDR block.
	 */
	private static function contains( string $address, string $block ): bool {
		list( $network, $prefixText ) = explode( '/', $block, 2 );
		$packedNetwork                = inet_pton( $network );
		$prefix                       = (int) $prefixText;
		if ( false === $packedNetwork || strlen( $address ) !== strlen( $packedNetwork ) ) {
			return false;
		}
		$bytes = intdiv( $prefix, 8 );
		if ( substr( $address, 0, $bytes ) !== substr( $packedNetwork, 0, $bytes ) ) {
			return false;
		}
		$bits = $prefix % 8;
		if ( 0 === $bits ) {
			return true;
		}
		$mask = ( 0xff << ( 8 - $bits ) ) & 0xff;

		return ( ord( $address[ $bytes ] ) & $mask ) === ( ord( $packedNetwork[ $bytes ] ) & $mask );
	}

	/** Prevents direct construction. */
	private function __construct() {
	}
}
