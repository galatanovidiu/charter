<?php
/**
 * Disposable Slice 0 CIMD authorization boundary.
 *
 * @package GalatanOvidiu\Charter
 */

declare(strict_types=1);

namespace GalatanOvidiu\Charter\Tests\Prototype\CimdOutboundSafety;

use Closure;

/**
 * Proves that CIMD validation controls only new authorization metadata.
 *
 * @since 0.1.0
 */
final class AuthorizationBoundary {

	/**
	 * Complete synchronous validation boundary.
	 *
	 * @var Closure(string, int): array<string, mixed>
	 */
	private readonly Closure $validator;

	/**
	 * Authoritative and diagnostic cache boundary.
	 *
	 * @var SnapshotCache
	 */
	private SnapshotCache $cache;

	/**
	 * Consent document fingerprints keyed by exact Client Identifier.
	 *
	 * @var array<string, string>
	 */
	private array $consents = array();

	/**
	 * Creates the local authorization boundary.
	 *
	 * @param callable $validator Complete validation boundary.
	 * @phpstan-param callable(string, int): array<string, mixed> $validator
	 */
	public function __construct( callable $validator ) {
		$this->validator = Closure::fromCallable( $validator );
		$this->cache     = new SnapshotCache();
	}

	/**
	 * Seeds one proof-owned validated snapshot.
	 *
	 * @param string   $clientId   Exact Client Identifier.
	 * @param string[] $redirects  Exact redirect set.
	 * @param string   $fingerprint Document fingerprint.
	 * @param int      $freshUntil  Exclusive freshness boundary.
	 * @phpstan-param list<string> $redirects
	 */
	public function seedValidatedSnapshot(
		string $clientId,
		array $redirects,
		string $fingerprint,
		int $freshUntil
	): void {
		$this->cache->storeAuthoritative( $clientId, $redirects, $fingerprint, $freshUntil );
	}

	/**
	 * Records consent against one validated document fingerprint.
	 *
	 * @param string $clientId    Exact Client Identifier.
	 * @param string $fingerprint Consented fingerprint.
	 */
	public function recordConsent( string $clientId, string $fingerprint ): void {
		$this->consents[ $clientId ] = $fingerprint;
	}

	/**
	 * Authorizes from fresh local state or after complete synchronous validation.
	 *
	 * @param string $clientId   Exact Client Identifier.
	 * @param string $redirectUri Requested redirect URI.
	 * @param int    $now         Current wall-clock second.
	 * @return array{classification:string, transaction_created:bool, consent_reusable:bool, snapshot_authoritative:bool, stale_fallback_used:bool, cimd_counters:array{dns:int,tcp:int,tls:int,http:int}} Result.
	 */
	public function authorize( string $clientId, string $redirectUri, int $now ): array {
		$hadAuthoritative = $this->cache->hasAuthoritative( $clientId );
		$snapshot         = $this->cache->fresh( $clientId, $now );
		$counters         = self::zeroCounters();

		if ( null === $snapshot ) {
			$validation  = ( $this->validator )( $clientId, $now );
			$counters    = self::validatedCounters( $validation['cimd_counters'] ?? null );
			$redirects   = self::validatedRedirects( $validation['redirect_uris'] ?? null );
			$fingerprint = $validation['fingerprint'] ?? null;
			$freshUntil  = $validation['fresh_until'] ?? null;
			$reusable    = $validation['reusable'] ?? null;
			$store       = $validation['store'] ?? null;

			if (
				'validated' !== ( $validation['classification'] ?? null )
				|| ( $validation['client_id'] ?? null ) !== $clientId
				|| null === $redirects
				|| ! is_string( $fingerprint )
				|| 1 !== preg_match( '/\A[a-f0-9]{64}\z/', $fingerprint )
				|| ! is_int( $freshUntil )
				|| ! is_bool( $reusable )
				|| ! is_bool( $store )
				|| ( $reusable && $now >= $freshUntil )
			) {
				if ( $hadAuthoritative ) {
					$state = $this->cache->observation( $clientId );
					$this->cache->storeDiagnostic(
						$clientId,
						$state['fingerprint'],
						'validation_failed',
						$now
					);
				}
				return self::result( 'validation_failed', false, false, false, $counters );
			}

			$snapshot = array(
				'redirects'   => $redirects,
				'fingerprint' => $fingerprint,
				'fresh_until' => $freshUntil,
			);

			if ( ! $store ) {
				$this->cache->clear( $clientId );
			} elseif ( $reusable ) {
				$this->cache->storeAuthoritative( $clientId, $redirects, $fingerprint, $freshUntil );
			} else {
				$this->cache->storeDiagnostic(
					$clientId,
					$fingerprint,
					is_string( $validation['cache_classification'] ?? null )
						? $validation['cache_classification']
						: 'revalidation_required',
					$now
				);
			}
		}

		$consentReusable = ( $this->consents[ $clientId ] ?? null ) === $snapshot['fingerprint'];
		if ( ! in_array( $redirectUri, $snapshot['redirects'], true ) ) {
			return self::result( 'local_reject', false, false, true, $counters );
		}

		return self::result( 'transaction_created', true, $consentReusable, true, $counters );
	}

	/**
	 * Returns body-free cache state for the proof assertions.
	 *
	 * @param string $clientId Exact Client Identifier.
	 * @return array{classification:string, redirect_count:int, fingerprint:string, fresh_until:int} State.
	 */
	public function snapshotState( string $clientId ): array {
		return $this->cache->observation( $clientId );
	}

	/**
	 * Checks a validator-provided exact redirect set.
	 *
	 * @param mixed $redirects Candidate redirect set.
	 * @return string[]|null Validated redirects.
	 * @phpstan-return list<string>|null
	 */
	private static function validatedRedirects( mixed $redirects ): ?array {
		if ( ! is_array( $redirects ) || ! array_is_list( $redirects ) || array() === $redirects ) {
			return null;
		}

		foreach ( $redirects as $redirect ) {
			if ( ! is_string( $redirect ) || '' === $redirect ) {
				return null;
			}
		}

		return $redirects;
	}

	/**
	 * Accepts only the fixed sanitized counter shape.
	 *
	 * @param mixed $counters Candidate counters.
	 * @return array{dns:int,tcp:int,tls:int,http:int} Counters.
	 */
	private static function validatedCounters( mixed $counters ): array {
		if ( ! is_array( $counters ) ) {
			return self::zeroCounters();
		}

		$result = array();
		foreach ( array( 'dns', 'tcp', 'tls', 'http' ) as $name ) {
			$value           = $counters[ $name ] ?? null;
			$result[ $name ] = is_int( $value ) && $value >= 0 ? $value : 0;
		}

		return $result;
	}

	/**
	 * Returns the zero-activity observation.
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

	/**
	 * Builds one fixed authorization result.
	 *
	 * @param string                                  $classification Stable classification.
	 * @param bool                                    $created        Whether a transaction was created.
	 * @param bool                                    $consent        Whether prior consent is reusable.
	 * @param bool                                    $authoritative  Whether current metadata is authoritative.
	 * @param array{dns:int,tcp:int,tls:int,http:int} $counters       Sanitized CIMD counters.
	 * @return array{classification:string, transaction_created:bool, consent_reusable:bool, snapshot_authoritative:bool, stale_fallback_used:bool, cimd_counters:array{dns:int,tcp:int,tls:int,http:int}} Result.
	 */
	private static function result(
		string $classification,
		bool $created,
		bool $consent,
		bool $authoritative,
		array $counters
	): array {
		return array(
			'classification'         => $classification,
			'transaction_created'    => $created,
			'consent_reusable'       => $consent,
			'snapshot_authoritative' => $authoritative,
			'stale_fallback_used'    => false,
			'cimd_counters'          => $counters,
		);
	}
}
