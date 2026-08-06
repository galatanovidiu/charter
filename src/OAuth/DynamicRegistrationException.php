<?php
/**
 * Dynamic registration protocol failure.
 *
 * @package GalatanOvidiu\Charter
 */

declare(strict_types=1);

namespace GalatanOvidiu\Charter\OAuth;

use RuntimeException;

/**
 * Carries a bounded RFC 7591-shaped failure.
 *
 * @since 0.1.0
 */
final class DynamicRegistrationException extends RuntimeException {

	/**
	 * Creates one bounded registration failure.
	 *
	 * @param string   $error Protocol error.
	 * @param string   $description Public description.
	 * @param int      $status HTTP status.
	 * @param int|null $retryAfter Retry delay.
	 */
	public function __construct(
		private readonly string $error,
		string $description,
		private readonly int $status,
		private readonly ?int $retryAfter = null
	) {
		parent::__construct( $description );
	}

	/** Returns the protocol error code. */
	public function error(): string {
		return $this->error;
	}

	/** Returns the HTTP status. */
	public function status(): int {
		return $this->status;
	}

	/** Returns the Retry-After delay when throttled. */
	public function retryAfter(): ?int {
		return $this->retryAfter;
	}
}
