<?php
/**
 * Safe outbound host-resolution contract.
 *
 * @package GalatanOvidiu\Charter
 */

declare(strict_types=1);

namespace GalatanOvidiu\Charter\Security;

use GalatanOvidiu\Charter\OAuth\ClientMetadataResolutionException;

/** Resolves a DNS host to a complete screened terminal address set. */
interface HostAddressResolver {

	/**
	 * Resolves one complete terminal address set.
	 *
	 * @param string $host Validated DNS host.
	 * @return list<string> Complete globally usable A and AAAA answer set.
	 * @throws ClientMetadataResolutionException When resolution is unsafe or incomplete.
	 */
	public function resolve( string $host ): array;
}
