<?php
/**
 * OAuth rate-limit decision.
 *
 * @package GalatanOvidiu\Charter
 */

declare(strict_types=1);

namespace GalatanOvidiu\Charter\Security;

/**
 * Carries one atomic counter outcome.
 *
 * @since 0.1.0
 */
final class RateLimitDecision {

	/**
	 * Creates one counter outcome.
	 *
	 * @param bool $allowed Whether the request is allowed.
	 * @param int  $count Resulting counter.
	 * @param int  $limit Configured limit.
	 * @param int  $retryAfter Retry delay.
	 */
	public function __construct(
		private readonly bool $allowed,
		private readonly int $count,
		private readonly int $limit,
		private readonly int $retryAfter
	) {
	}

	/** Reports whether the request is allowed. */
	public function allowed(): bool {
		return $this->allowed;
	}

	/** Returns the resulting counter value. */
	public function count(): int {
		return $this->count;
	}

	/** Returns the configured limit. */
	public function limit(): int {
		return $this->limit;
	}

	/** Returns the bounded retry delay. */
	public function retryAfter(): int {
		return $this->retryAfter;
	}
}
