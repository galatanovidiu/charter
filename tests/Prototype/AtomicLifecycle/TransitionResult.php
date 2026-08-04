<?php
/**
 * Disposable Slice 0 transition result.
 *
 * @package GalatanOvidiu\Charter
 */

declare(strict_types=1);

namespace GalatanOvidiu\Charter\Tests\Prototype\AtomicLifecycle;

/**
 * Reports a fixed non-secret transition outcome.
 *
 * @since 0.1.0
 */
final class TransitionResult {

	public const WINNER = 'winner';

	public const REPLAY = 'replay';

	public const INVALID = 'invalid';

	/**
	 * Creates one sanitized transition result.
	 *
	 * @param string $status Fixed transition status.
	 * @param bool   $committed Whether the complete transition committed.
	 * @param int    $connectionId Numeric proof connection identifier.
	 */
	public function __construct(
		private readonly string $status,
		private readonly bool $committed,
		private readonly int $connectionId
	) {
	}

	/**
	 * Returns the fixed lifecycle outcome.
	 */
	public function status(): string {
		return $this->status;
	}

	/**
	 * Reports whether the whole transaction committed.
	 */
	public function committed(): bool {
		return $this->committed;
	}

	/**
	 * Returns the sanitized connection identifier.
	 */
	public function connectionId(): int {
		return $this->connectionId;
	}

	/**
	 * Returns a fixed-schema non-secret projection.
	 *
	 * @return array{status: string, committed: bool, connection_id: int}
	 */
	public function sanitized(): array {
		return array(
			'status'        => $this->status,
			'committed'     => $this->committed,
			'connection_id' => $this->connectionId,
		);
	}
}
