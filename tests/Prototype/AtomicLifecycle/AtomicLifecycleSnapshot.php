<?php
/**
 * Disposable Slice 0 sanitized lifecycle snapshot.
 *
 * @package GalatanOvidiu\Charter
 */

declare(strict_types=1);

namespace GalatanOvidiu\Charter\Tests\Prototype\AtomicLifecycle;

use LogicException;

/**
 * Exposes lifecycle state without credential material or digests.
 *
 * @since 0.1.0
 */
final class AtomicLifecycleSnapshot {

	/**
	 * Creates one sanitized snapshot and opaque comparison value.
	 *
	 * @param array<string, int|string|bool|array<string, int|string|bool>> $state Sanitized state.
	 * @param string                                                        $fingerprint Opaque comparison fingerprint.
	 */
	public function __construct(
		private readonly array $state,
		private readonly string $fingerprint
	) {
	}

	/**
	 * Returns the authorization-code state.
	 */
	public function codeState(): string {
		return $this->stringValue( 'code_state' );
	}

	/**
	 * Returns the primary grant state.
	 */
	public function grantState(): string {
		return $this->stringValue( 'grant_state' );
	}

	/**
	 * Returns the primary refresh-family state.
	 */
	public function familyState(): string {
		return $this->stringValue( 'family_state' );
	}

	/**
	 * Returns the primary family's current generation.
	 */
	public function familyCurrentGeneration(): int {
		return $this->intValue( 'family_current_generation' );
	}

	/**
	 * Returns the number of committed lineages for the primary code.
	 */
	public function committedCodeLineageCount(): int {
		return $this->intValue( 'committed_code_lineage_count' );
	}

	/**
	 * Returns the number of currently valid descendants issued from the code.
	 */
	public function validCodeDescendantCount(): int {
		return $this->intValue( 'valid_code_descendant_count' );
	}

	/**
	 * Returns the primary grant's active access-descendant count.
	 */
	public function activeAccessCount(): int {
		return $this->intValue( 'active_access_count' );
	}

	/**
	 * Returns the primary family's current-member count.
	 */
	public function currentRefreshCount(): int {
		return $this->intValue( 'current_refresh_count' );
	}

	/**
	 * Returns the idempotent code-replay event count.
	 */
	public function codeReplayEventCount(): int {
		return $this->intValue( 'code_replay_event_count' );
	}

	/**
	 * Returns the idempotent refresh-replay event count.
	 */
	public function refreshReplayEventCount(): int {
		return $this->intValue( 'refresh_replay_event_count' );
	}

	/**
	 * Returns exact public proof bindings.
	 *
	 * @return array<string, int|string|bool>
	 */
	public function bindings(): array {
		return $this->arrayValue( 'bindings' );
	}

	/**
	 * Returns the unrelated domain's non-secret semantic state.
	 *
	 * @return array<string, int|string|bool>
	 */
	public function unrelatedState(): array {
		return $this->arrayValue( 'unrelated_state' );
	}

	/**
	 * Returns an opaque fingerprint for equality checks only.
	 */
	public function fingerprint(): string {
		return $this->fingerprint;
	}

	/**
	 * Returns a fixed-schema projection that contains no fingerprint.
	 *
	 * @return array<string, int|string|bool|array<string, int|string|bool>>
	 */
	public function sanitized(): array {
		return $this->state;
	}

	/**
	 * Returns one required string field.
	 *
	 * @param string $key Fixed state key.
	 * @throws LogicException When the snapshot shape is invalid.
	 */
	private function stringValue( string $key ): string {
		$value = $this->state[ $key ] ?? null;

		if ( ! is_string( $value ) ) {
			throw new LogicException( 'Invalid disposable lifecycle snapshot string.' );
		}

		return $value;
	}

	/**
	 * Returns one required integer field.
	 *
	 * @param string $key Fixed state key.
	 * @throws LogicException When the snapshot shape is invalid.
	 */
	private function intValue( string $key ): int {
		$value = $this->state[ $key ] ?? null;

		if ( ! is_int( $value ) ) {
			throw new LogicException( 'Invalid disposable lifecycle snapshot integer.' );
		}

		return $value;
	}

	/**
	 * Returns one required nested state projection.
	 *
	 * @param string $key Fixed state key.
	 * @return array<string, int|string|bool>
	 * @throws LogicException When the snapshot shape is invalid.
	 */
	private function arrayValue( string $key ): array {
		$value = $this->state[ $key ] ?? null;

		if ( ! is_array( $value ) ) {
			throw new LogicException( 'Invalid disposable lifecycle snapshot projection.' );
		}

		return $value;
	}
}
