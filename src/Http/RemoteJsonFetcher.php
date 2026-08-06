<?php
/**
 * Direct bounded JSON fetch contract.
 *
 * @package GalatanOvidiu\Charter
 */

declare(strict_types=1);

namespace GalatanOvidiu\Charter\Http;

use GalatanOvidiu\Charter\OAuth\ClientMetadataIdentifier;
use GalatanOvidiu\Charter\OAuth\ClientMetadataResolutionException;

/** Fetches one exact URL only after transport preflight and address screening. */
interface RemoteJsonFetcher {

	/**
	 * Verifies that the exact safe transport policy can be enforced.
	 *
	 * @throws ClientMetadataResolutionException When direct safe transport is unavailable.
	 */
	public function assertAvailable(): void;

	/**
	 * Fetches one exact metadata URL through a screened connection.
	 *
	 * @param ClientMetadataIdentifier $identifier Exact submitted identifier.
	 * @param array                    $screenedAddresses Complete screened terminal addresses.
	 * @phpstan-param list<string> $screenedAddresses
	 * @throws ClientMetadataResolutionException When the response is not authoritative.
	 */
	public function fetch( ClientMetadataIdentifier $identifier, array $screenedAddresses ): BoundedHttpResponse;
}
