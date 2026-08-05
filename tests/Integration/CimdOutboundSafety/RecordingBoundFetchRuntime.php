<?php
/**
 * Pure recording double for the bounded WordPress HTTP runtime.
 *
 * @package GalatanOvidiu\Charter
 */

declare(strict_types=1);

namespace GalatanOvidiu\Charter\Tests\Integration\CimdOutboundSafety;

use GalatanOvidiu\Charter\Tests\Prototype\CimdOutboundSafety\BoundFetchRuntime;
use GalatanOvidiu\Charter\Tests\Prototype\CimdOutboundSafety\ClientIdentifier;
use RuntimeException;

/**
 * Records fetch orchestration without installing WordPress hooks.
 *
 * @since 0.1.0
 */
final class RecordingBoundFetchRuntime extends BoundFetchRuntime {

	/**
	 * Ordered runtime events.
	 *
	 * @var list<string>
	 */
	public array $events = array();

	/**
	 * Screened peers supplied to the runtime.
	 *
	 * @var list<string>
	 */
	public array $screenedAddresses = array();

	/**
	 * Fixed hardening policy supplied to the runtime.
	 *
	 * @var array<string, mixed>
	 */
	public array $policy = array();

	/**
	 * Scripted capability result.
	 *
	 * @var string
	 */
	public string $preflightResult = 'ready';

	/**
	 * Optional foreign dispatch error.
	 *
	 * @var RuntimeException|null
	 */
	public ?RuntimeException $dispatchError = null;

	/**
	 * Optional fixed observation returned by dispatch.
	 *
	 * @var array<string, mixed>|null
	 */
	public ?array $observation = null;

	/**
	 * Creates the recording runtime with an inert CA path.
	 */
	public function __construct() {
		parent::__construct( '/proof/ca.pem' );
	}

	/**
	 * Records the preflight.
	 *
	 * @return string Scripted classification.
	 */
	public function preflight(): string {
		$this->events[] = 'preflight';
		return $this->preflightResult;
	}

	/**
	 * Records the bounded request scope.
	 *
	 * @param ClientIdentifier     $id                Exact client identifier.
	 * @param string[]             $screenedAddresses Screened peers.
	 * @param array<string, mixed> $policy            Fixed policy.
	 * @phpstan-param list<string> $screenedAddresses
	 */
	public function begin( ClientIdentifier $id, array $screenedAddresses, array $policy ): void {
		unset( $id );
		$this->events[]          = 'begin';
		$this->screenedAddresses = $screenedAddresses;
		$this->policy            = $policy;
	}

	/**
	 * Returns one scripted completed request.
	 *
	 * @return array<string, mixed> Bounded observation.
	 * @throws RuntimeException When the scripted foreign failure is set.
	 */
	public function dispatch(): array {
		$this->events[] = 'dispatch';
		if ( null !== $this->dispatchError ) {
			throw $this->dispatchError;
		}

		return $this->observation ?? self::completeObservation();
	}

	/**
	 * Records cleanup of the request scope.
	 */
	public function end(): void {
		$this->events[] = 'end';
	}

	/**
	 * Returns one fixed successful observation.
	 *
	 * @return array<string, mixed> Completed observation.
	 */
	public static function completeObservation(): array {
		return array(
			'classification'        => 'complete',
			'status_code'           => 200,
			'body'                  => '{}',
			'headers'               => array( 'content-type' => array( 'application/json' ) ),
			'body_bytes'            => 2,
			'header_bytes'          => 36,
			'header_fields'         => 1,
			'elapsed_ms'            => 1,
			'request_count'         => 1,
			'redirect_followed'     => false,
			'peer_matched'          => true,
			'tls_hostname_verified' => true,
			'media_classification'  => 'accepted',
			'content_coding'        => 'identity',
		);
	}
}
