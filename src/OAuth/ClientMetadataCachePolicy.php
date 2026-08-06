<?php
/**
 * CIMD response cache decision.
 *
 * @package GalatanOvidiu\Charter
 */

declare(strict_types=1);

namespace GalatanOvidiu\Charter\OAuth;

/** Carries the exclusive freshness boundary and reusable-storage decision. */
final class ClientMetadataCachePolicy {

	/**
	 * Creates one cache decision.
	 *
	 * @param int  $freshUntil Exclusive freshness boundary.
	 * @param bool $reusable Whether the projection may be stored.
	 */
	public function __construct(
		private readonly int $freshUntil,
		private readonly bool $reusable
	) {
	}

	/** Returns the exclusive freshness boundary. */
	public function freshUntil(): int {
		return $this->freshUntil;
	}

	/** Reports whether the projection may be stored. */
	public function reusable(): bool {
		return $this->reusable;
	}
}
