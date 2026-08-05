<?php
/**
 * Proof-owned exit from the Requests cURL transport.
 *
 * @package GalatanOvidiu\Charter
 */

declare(strict_types=1);

namespace GalatanOvidiu\Charter\Tests\Prototype\CimdOutboundSafety;

use RuntimeException;

/**
 * Carries only the fixed, bounded observation made after one cURL send.
 *
 * @since 0.1.0
 */
final class BoundFetchException extends RuntimeException {

	/**
	 * Fixed bounded observation.
	 *
	 * @var array<string, mixed>
	 */
	private array $observation;

	/**
	 * Creates the proof-owned transport exit.
	 *
	 * @param array<string, mixed> $observation Fixed bounded observation.
	 */
	public function __construct( array $observation ) {
		parent::__construct( 'The bounded CIMD fetch completed.' );
		$this->observation = $observation;
	}

	/**
	 * Returns the fixed bounded observation.
	 *
	 * @return array<string, mixed> Fixed bounded observation.
	 */
	public function observation(): array {
		return $this->observation;
	}
}
