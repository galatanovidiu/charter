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
		$remote = $_SERVER['REMOTE_ADDR'] ?? null; // phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotSanitized,WordPress.Security.ValidatedSanitizedInput.MissingUnslash -- Raw server transport metadata is parsed strictly as an IP address and never displayed directly.
		if ( ! is_string( $remote ) ) {
			return 'unknown';
		}

		$packed = inet_pton( $remote );
		if ( false === $packed ) {
			return 'unknown';
		}
		if ( 16 === strlen( $packed ) ) {
			$packed = substr( $packed, 0, 8 ) . str_repeat( "\0", 8 );
		}

		$normalized = inet_ntop( $packed );
		return is_string( $normalized ) ? $normalized : 'unknown';
	}

	/** This class contains static normalization only. */
	private function __construct() {
	}
}
