<?php
/**
 * Disposable Slice 0 transition coordinator and fault control.
 *
 * @package GalatanOvidiu\Charter
 */

declare(strict_types=1);

namespace GalatanOvidiu\Charter\Tests\Prototype\AtomicLifecycle;

use Closure;

/**
 * Emits deterministic checkpoints and injects fixed pre-commit failures.
 *
 * @since 0.1.0
 */
final class TransitionControl {

	/**
	 * Creates one deterministic transition control.
	 *
	 * @param Closure(string, int): void|null $checkpointObserver Coordinator callback.
	 * @param array                           $failAt Checkpoints that throw a fixed failure.
	 * @phpstan-param list<string> $failAt
	 */
	public function __construct(
		private readonly ?Closure $checkpointObserver = null,
		private readonly array $failAt = array()
	) {
	}

	/**
	 * Emits one checkpoint and optionally injects a failure.
	 *
	 * @param string $checkpoint Fixed checkpoint name.
	 * @param int    $connectionId Numeric proof connection identifier.
	 * @throws TransitionFailure When this checkpoint is configured to fail.
	 */
	public function reach( string $checkpoint, int $connectionId ): void {
		if ( $this->checkpointObserver instanceof Closure ) {
			( $this->checkpointObserver )( $checkpoint, $connectionId );
		}

		if ( in_array( $checkpoint, $this->failAt, true ) ) {
			// phpcs:ignore WordPress.Security.EscapeOutput.ExceptionNotEscaped -- The fixed exception copies only a numeric connection identifier.
			throw TransitionFailure::injected( $connectionId );
		}
	}
}
