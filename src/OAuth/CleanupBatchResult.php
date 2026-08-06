<?php
/**
 * Bounded OAuth retention result.
 *
 * @package GalatanOvidiu\Charter
 */

declare(strict_types=1);

namespace GalatanOvidiu\Charter\OAuth;

/**
 * Carries non-secret counts from one issuer-local cleanup batch.
 *
 * @since 0.1.0
 */
final class CleanupBatchResult {

	/**
	 * Creates one bounded result.
	 *
	 * @param array<string, int> $deleted Deleted rows by retention category.
	 * @param bool               $hasMore Whether another bounded batch is eligible.
	 */
	public function __construct(
		private readonly array $deleted,
		private readonly bool $hasMore
	) {
	}

	/**
	 * Returns deleted row counts by category.
	 *
	 * @return array<string, int>
	 */
	public function deleted(): array {
		return $this->deleted;
	}

	/** Returns the complete number of rows deleted in this batch. */
	public function totalDeleted(): int {
		return array_sum( $this->deleted );
	}

	/** Reports whether another eligible batch remains. */
	public function hasMore(): bool {
		return $this->hasMore;
	}
}
