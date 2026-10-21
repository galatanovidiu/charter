<?php
/**
 * OAuth abuse-source normalization.
 *
 * @package GalatanOvidiu\Charter
 */

declare(strict_types=1);

namespace GalatanOvidiu\Charter\Security;

/**
 * Uses only the direct peer until a trusted-proxy policy is configured.
 *
 * @since 0.1.0
 */
final class SourceAddress {

	/**
	 * Returns a stable direct-peer bucket, grouping IPv6 by /64.
	 *
	 * @since 0.1.0
	 */
	public static function current(): string {
		return ( new TrustedProxyPolicy() )->sourceAddress( $_SERVER );
	}

	/** This class contains static normalization only. */
	private function __construct() {
	}
}
