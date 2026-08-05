<?php
/**
 * One-dispatch WordPress HTTP fetch orchestration.
 *
 * @package GalatanOvidiu\Charter
 */

declare(strict_types=1);

namespace GalatanOvidiu\Charter\Tests\Prototype\CimdOutboundSafety;

/**
 * Applies the fixed proof policy and guarantees request-scope cleanup.
 *
 * @since 0.1.0
 */
final class BoundWordPressHttpFetcher {

	/**
	 * Creates an orchestrator around the proof runtime boundary.
	 *
	 * @param BoundFetchRuntime $runtime Proof runtime boundary.
	 */
	public function __construct( private BoundFetchRuntime $runtime ) {}

	/**
	 * Runs one bounded fetch and always removes the request scope.
	 *
	 * @param ClientIdentifier $id                Exact Client Identifier.
	 * @param array            $screenedAddresses Complete screened address set.
	 * @phpstan-param list<string> $screenedAddresses
	 */
	public function fetch( ClientIdentifier $id, array $screenedAddresses ): BoundFetchResult {
		$preflight = $this->runtime->preflight();

		if ( 'ready' !== $preflight ) {
			return BoundFetchResult::fromObservation( self::emptyObservation( $preflight ) );
		}

		$this->runtime->begin( $id, $screenedAddresses, self::policy() );

		try {
			return BoundFetchResult::fromObservation( $this->runtime->dispatch() );
		} finally {
			$this->runtime->end();
		}
	}

	/**
	 * Returns the exact approved request policy.
	 *
	 * @return array<string, mixed> Fixed request policy.
	 */
	private static function policy(): array {
		return array(
			'method'                   => 'GET',
			'timeout'                  => 5,
			'connect_timeout'          => 3,
			'redirection'              => 0,
			'sslverify'                => true,
			'blocking'                 => true,
			'decompress'               => false,
			'cookies'                  => array(),
			'body'                     => null,
			'accept'                   => 'application/json',
			'accept_encoding'          => 'identity',
			'cache_control'            => 'no-cache',
			'user_agent'               => 'Charter-CIMD-Proof/1',
			'max_header_bytes'         => 32768,
			'max_header_fields'        => 128,
			'max_header_line_bytes'    => 8192,
			'max_body_bytes'           => 5120,
			'follow_location'          => false,
			'max_redirects'            => 0,
			'fresh_connect'            => true,
			'forbid_reuse'             => true,
			'automatic_content_coding' => false,
		);
	}

	/**
	 * Creates a body-free preflight-failure observation.
	 *
	 * @param string $classification Stable preflight classification.
	 * @return array<string, mixed> Fixed empty observation.
	 */
	private static function emptyObservation( string $classification ): array {
		return array(
			'classification'        => $classification,
			'status_code'           => null,
			'body'                  => '',
			'headers'               => array(),
			'body_bytes'            => 0,
			'header_bytes'          => 0,
			'header_fields'         => 0,
			'elapsed_ms'            => 0,
			'request_count'         => 0,
			'redirect_followed'     => false,
			'peer_matched'          => false,
			'tls_hostname_verified' => false,
			'media_classification'  => 'unavailable',
			'content_coding'        => 'unavailable',
		);
	}
}
