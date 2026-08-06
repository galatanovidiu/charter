<?php
/**
 * Static CIMD host resolver integration fixture.
 *
 * @package GalatanOvidiu\Charter
 */

declare(strict_types=1);

namespace GalatanOvidiu\Charter\Tests\Integration\OAuth;

use GalatanOvidiu\Charter\Security\HostAddressResolver;

/** Returns one fixed globally usable address without touching the network. */
final class StaticHostAddressResolver implements HostAddressResolver {

	/**
	 * Returns one fixed globally usable address.
	 *
	 * @param string $host Validated DNS host.
	 * @return list<string> Fixed terminal answer set.
	 */
	public function resolve( string $host ): array {
		unset( $host );

		return array( '8.8.8.8' );
	}
}
