<?php
/**
 * Authorization-time Client ID Metadata Document resolution.
 *
 * @package GalatanOvidiu\Charter
 */

declare(strict_types=1);

namespace GalatanOvidiu\Charter\OAuth;

use GalatanOvidiu\Charter\Http\RemoteJsonFetcher;
use GalatanOvidiu\Charter\Security\HostAddressResolver;
use InvalidArgumentException;
use RuntimeException;

/** Keeps mutable remote metadata entirely outside established credential paths. */
final class ClientMetadataResolver {

	/**
	 * Creates the authorization-time resolver.
	 *
	 * @param ClientRegistry              $clients Client lifecycle registry.
	 * @param ClientMetadataSnapshotStore $snapshots Reusable validated projections.
	 * @param HostAddressResolver         $addresses Complete screened DNS boundary.
	 * @param RemoteJsonFetcher           $fetcher Direct bounded JSON transport.
	 */
	public function __construct(
		private readonly ClientRegistry $clients,
		private readonly ClientMetadataSnapshotStore $snapshots,
		private readonly HostAddressResolver $addresses,
		private readonly RemoteJsonFetcher $fetcher
	) {
	}

	/**
	 * Resolves a fixed/DCR client locally or validates a CIMD client for authorization.
	 *
	 * @param string $issuer Exact issuer.
	 * @param string $clientId Exact submitted client identifier.
	 * @param int    $timestamp Current timestamp.
	 * @throws ClientMetadataResolutionException When a valid CIMD identity cannot be refreshed safely.
	 */
	public function resolveForAuthorization( string $issuer, string $clientId, int $timestamp ): ?Client {
		$registration = $this->clients->findRegistration( $issuer, $clientId );
		if ( null !== $registration ) {
			if ( ClientRegistry::STATUS_ACTIVE !== $registration->status() ) {
				return null;
			}
			if ( ClientRegistry::SOURCE_CIMD !== $registration->source() ) {
				return $this->clients->findActive( $issuer, $clientId );
			}
		}

		try {
			$identifier = ClientMetadataIdentifier::fromString( $clientId );
		} catch ( InvalidArgumentException ) {
			return null;
		}

		$snapshot = $this->snapshots->findFresh( $issuer, $clientId, $timestamp );
		if ( null !== $snapshot ) {
			return $snapshot->client( $issuer );
		}

		$this->fetcher->assertAvailable();
		$addresses = $this->addresses->resolve( $identifier->host() );
		$response  = $this->fetcher->fetch( $identifier, $addresses );
		try {
			$metadata = ClientMetadataDocumentValidator::validate( $response->body(), $identifier );
		} catch ( InvalidArgumentException ) {
			throw new ClientMetadataResolutionException( 'metadata_invalid' );
		}

		try {
			if ( ! $this->clients->ensureCimdClient( $issuer, $clientId, $timestamp ) ) {
				return null;
			}
			$policy = ClientMetadataFreshness::evaluate( $response->headers(), $response->requestTime(), $response->responseTime(), $timestamp );
			if ( $policy->reusable() ) {
				$this->snapshots->store( $issuer, $metadata, $response->responseTime(), $policy->freshUntil() );
			} else {
				$this->snapshots->delete( $issuer, $clientId );
			}
		} catch ( RuntimeException ) {
			throw new ClientMetadataResolutionException( 'persistence_failed' );
		}

		return $metadata->client( $issuer );
	}
}
