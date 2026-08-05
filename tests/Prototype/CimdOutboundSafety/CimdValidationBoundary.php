<?php
/**
 * Disposable complete CIMD validation boundary.
 *
 * @package GalatanOvidiu\Charter
 */

declare(strict_types=1);

namespace GalatanOvidiu\Charter\Tests\Prototype\CimdOutboundSafety;

use Closure;
use InvalidArgumentException;

/**
 * Composes exact identity, resolution, screening, bound fetch, metadata, and freshness.
 *
 * @since 0.1.0
 */
final class CimdValidationBoundary {

	/**
	 * Injected wall-clock boundary used immediately before and after dispatch.
	 *
	 * @var Closure(): int
	 */
	private readonly Closure $wallClock;

	/**
	 * Creates the synchronous validation composition.
	 *
	 * @param BoundedResolver           $resolver  Complete bounded resolver.
	 * @param BoundWordPressHttpFetcher $fetcher   Bound WordPress HTTP fetcher.
	 * @param callable                  $wallClock Injected wall-clock seconds.
	 * @phpstan-param callable(): int $wallClock
	 */
	public function __construct(
		private readonly BoundedResolver $resolver,
		private readonly BoundWordPressHttpFetcher $fetcher,
		callable $wallClock
	) {
		$this->wallClock = Closure::fromCallable( $wallClock );
	}

	/**
	 * Runs the complete operation synchronously for one new authorization.
	 *
	 * @param string $clientId Exact submitted Client Identifier.
	 * @param int    $now      Current authorization wall-clock second.
	 * @return array<string, mixed> Sanitized authorization-boundary result.
	 */
	public function validate( string $clientId, int $now ): array {
		try {
			$identifier = ClientIdentifier::fromString( $clientId );
		} catch ( InvalidArgumentException ) {
			return self::failure( $clientId, 'client_identifier', self::zeroCounters() );
		}

		$resolution = $this->resolver->resolve( $identifier->host() );
		$counters   = array(
			'dns'  => $resolution['query_count'],
			'tcp'  => 0,
			'tls'  => 0,
			'http' => 0,
		);

		if ( 'resolved' !== $resolution['classification'] ) {
			return self::failure( $clientId, 'dns_' . $resolution['classification'], $counters );
		}

		$requestTime  = ( $this->wallClock )();
		$result       = $this->fetcher->fetch( $identifier, $resolution['addresses'] );
		$responseTime = ( $this->wallClock )();

		$counters['tcp']  = $result->requestCount() > 0 || $result->peerMatched() ? 1 : 0;
		$counters['tls']  = $result->tlsHostnameVerified() ? 1 : 0;
		$counters['http'] = $result->requestCount();

		if (
			'complete' !== $result->classification()
			|| 200 !== $result->statusCode()
			|| 1 !== $result->requestCount()
			|| $result->redirectFollowed()
			|| ! $result->peerMatched()
			|| ! $result->tlsHostnameVerified()
			|| 'accepted' !== $result->mediaClassification()
			|| ! in_array( $result->contentCodingClassification(), array( 'absent', 'identity' ), true )
		) {
			return self::failure( $clientId, 'fetch_' . $result->classification(), $counters );
		}

		try {
			$metadata = MetadataValidator::validate( $result->body(), $identifier );
		} catch ( InvalidArgumentException ) {
			return self::failure( $clientId, 'metadata_invalid', $counters );
		}

		$freshness = FreshnessPolicy::evaluate( $result->headers(), $requestTime, $responseTime, $now );

		return array(
			'classification'         => 'validated',
			'failure_classification' => 'none',
			'client_id'              => $metadata->clientId(),
			'redirect_uris'          => $metadata->redirectUris(),
			'fingerprint'            => $metadata->fingerprint(),
			'fresh_until'            => $freshness['fresh_until'],
			'reusable'               => $freshness['reusable'],
			'store'                  => $freshness['store'],
			'cache_classification'   => $freshness['classification'],
			'cimd_counters'          => $counters,
		);
	}

	/**
	 * Returns one fixed failure without redirects or document content.
	 *
	 * @param string                                  $clientId       Submitted identity.
	 * @param string                                  $classification Stable failure.
	 * @param array{dns:int,tcp:int,tls:int,http:int} $counters       Sanitized counters.
	 * @return array<string, mixed> Failure result.
	 */
	private static function failure( string $clientId, string $classification, array $counters ): array {
		return array(
			'classification'         => 'failed',
			'failure_classification' => $classification,
			'client_id'              => $clientId,
			'redirect_uris'          => array(),
			'fingerprint'            => 'none',
			'fresh_until'            => 0,
			'reusable'               => false,
			'store'                  => false,
			'cache_classification'   => 'unavailable',
			'cimd_counters'          => $counters,
		);
	}

	/**
	 * Returns the zero-activity counter shape.
	 *
	 * @return array{dns:int,tcp:int,tls:int,http:int} Counters.
	 */
	private static function zeroCounters(): array {
		return array(
			'dns'  => 0,
			'tcp'  => 0,
			'tls'  => 0,
			'http' => 0,
		);
	}
}
