<?php
/**
 * Sequenced CIMD transport integration fixture.
 *
 * @package GalatanOvidiu\Charter
 */

declare(strict_types=1);

namespace GalatanOvidiu\Charter\Tests\Integration\OAuth;

use GalatanOvidiu\Charter\Http\BoundedHttpResponse;
use GalatanOvidiu\Charter\Http\RemoteJsonFetcher;
use GalatanOvidiu\Charter\OAuth\ClientMetadataIdentifier;
use GalatanOvidiu\Charter\OAuth\ClientMetadataResolutionException;

/** Returns a deterministic sequence of complete transport responses or failures. */
final class SequenceRemoteJsonFetcher implements RemoteJsonFetcher {

	/**
	 * Remaining responses or failures.
	 *
	 * @var list<array{body:string,headers:array<string,list<string>>}|ClientMetadataResolutionException>
	 */
	private array $responses;

	/**
	 * Completed fetch attempts.
	 *
	 * @var int
	 */
	private int $fetchCount = 0;

	/**
	 * Exact identifiers accepted by this fixture.
	 *
	 * @var list<string>
	 */
	private array $clientIds;

	/**
	 * Creates one deterministic response sequence.
	 *
	 * @param array $responses Responses or failures.
	 * @param array $clientIds Exact accepted identifiers.
	 * @phpstan-param list<array{body:string,headers:array<string,list<string>>}|ClientMetadataResolutionException> $responses
	 * @phpstan-param list<string> $clientIds
	 */
	public function __construct( array $responses, array $clientIds = array( 'https://metadata.example.test/client.json' ) ) {
		$this->responses = $responses;
		$this->clientIds = $clientIds;
	}

	/** Verifies the deterministic fixture is available. */
	public function assertAvailable(): void {
	}

	/**
	 * Returns or throws the next deterministic result.
	 *
	 * @param ClientMetadataIdentifier $identifier Exact submitted identifier.
	 * @param array                    $screenedAddresses Complete screened terminal addresses.
	 * @phpstan-param list<string> $screenedAddresses
	 * @throws ClientMetadataResolutionException When the fixture result is a failure.
	 */
	public function fetch( ClientMetadataIdentifier $identifier, array $screenedAddresses ): BoundedHttpResponse {
		if ( ! in_array( $identifier->exact(), $this->clientIds, true ) || array( '8.8.8.8' ) !== $screenedAddresses ) {
			throw new ClientMetadataResolutionException( 'transport_failed' );
		}
		++$this->fetchCount;
		$response = array_shift( $this->responses );
		if ( $response instanceof ClientMetadataResolutionException ) {
			throw $response;
		}
		if ( ! is_array( $response ) ) {
			throw new ClientMetadataResolutionException( 'transport_failed' );
		}
		$timestamp = time();

		return new BoundedHttpResponse( $response['body'], $response['headers'], $timestamp, $timestamp );
	}

	/** Returns completed fetch attempts. */
	public function fetchCount(): int {
		return $this->fetchCount;
	}
}
