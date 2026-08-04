<?php
/**
 * Disposable Slice 0 explicit-key guard seam.
 *
 * @package GalatanOvidiu\Charter
 */

declare(strict_types=1);

namespace GalatanOvidiu\Charter\Tests\Prototype\Multisite;

/**
 * Models explicit-key matching, mismatch, restore, and adoption behavior.
 *
 * The fingerprint and generation representation are disposable proof state.
 * They do not select a production schema, format, or operator workflow.
 *
 * @since 0.1.0
 */
final class ExplicitKeyGuard {

	/**
	 * No explicit key has been established.
	 *
	 * @since 0.1.0
	 *
	 * @var string
	 */
	public const UNESTABLISHED = 'unestablished';

	/**
	 * The supplied explicit snapshot matches accepted proof state.
	 *
	 * @since 0.1.0
	 *
	 * @var string
	 */
	public const MATCHING = 'matching';

	/**
	 * The supplied explicit snapshot mismatches accepted proof state.
	 *
	 * @since 0.1.0
	 *
	 * @var string
	 */
	public const MISMATCH = 'mismatch';

	/**
	 * The supplied source is not an explicit configuration snapshot.
	 *
	 * @since 0.1.0
	 *
	 * @var string
	 */
	public const NOT_EXPLICIT = 'not_explicit';

	/**
	 * Disposable network option used by the explicit-key proof.
	 *
	 * @since 0.1.0
	 *
	 * @var string
	 */
	private const STORE_OPTION = 'charter_slice0_explicit_key_guard';

	/**
	 * Establishes the first accepted explicit-key fingerprint.
	 *
	 * @since 0.1.0
	 *
	 * @param EffectiveRootKeySource $source The explicit configuration snapshot.
	 * @return bool Whether new guard state was established.
	 */
	public static function establish( EffectiveRootKeySource $source ): bool {
		if ( ! $source->usesExplicitSnapshot() || null !== self::state() ) {
			return false;
		}

		update_network_option(
			null,
			self::STORE_OPTION,
			array(
				'accepted_fingerprint' => $source->nonSecretFingerprint(),
				'generation'           => 0,
				'adoption_count'       => 0,
			)
		);

		return true;
	}

	/**
	 * Reports the current guard relationship without modifying proof state.
	 *
	 * @since 0.1.0
	 *
	 * @param EffectiveRootKeySource $source The current root snapshot.
	 * @return string One of this class's status constants.
	 */
	public static function statusFor( EffectiveRootKeySource $source ): string {
		if ( ! $source->usesExplicitSnapshot() ) {
			return self::NOT_EXPLICIT;
		}

		$state = self::state();

		if ( null === $state ) {
			return self::UNESTABLISHED;
		}

		return hash_equals( $state['accepted_fingerprint'], $source->nonSecretFingerprint() )
			? self::MATCHING
			: self::MISMATCH;
	}

	/**
	 * Reports whether credential issuance and validation may proceed.
	 *
	 * WordPress-derived mode needs no adoption. Every explicit operation is
	 * allowed only when its snapshot matches established guard state.
	 *
	 * @since 0.1.0
	 *
	 * @param EffectiveRootKeySource $source The current root snapshot.
	 * @return bool Whether credential operations may proceed.
	 */
	public static function allowsCredentialOperations( EffectiveRootKeySource $source ): bool {
		if ( ! $source->usesExplicitSnapshot() ) {
			return true;
		}

		return self::MATCHING === self::statusFor( $source );
	}

	/**
	 * Explicitly adopts one mismatching replacement snapshot.
	 *
	 * @since 0.1.0
	 *
	 * @param EffectiveRootKeySource $replacement The replacement snapshot.
	 * @return bool Whether replacement proof state was adopted.
	 */
	public static function adoptReplacement( EffectiveRootKeySource $replacement ): bool {
		if ( self::MISMATCH !== self::statusFor( $replacement ) ) {
			return false;
		}

		$state = self::state();

		if ( null === $state ) {
			return false;
		}

		update_network_option(
			null,
			self::STORE_OPTION,
			array(
				'accepted_fingerprint' => $replacement->nonSecretFingerprint(),
				'generation'           => $state['generation'] + 1,
				'adoption_count'       => $state['adoption_count'] + 1,
			)
		);

		return true;
	}

	/**
	 * Returns the number of explicit replacement adoptions.
	 *
	 * @since 0.1.0
	 *
	 * @return int The adoption count.
	 */
	public static function adoptionCount(): int {
		$state = self::state();

		return $state['adoption_count'] ?? 0;
	}

	/**
	 * Returns the disposable credential generation for proof-domain binding.
	 *
	 * @since 0.1.0
	 *
	 * @return int The current non-secret proof generation.
	 */
	public static function credentialGeneration(): int {
		$state = self::state();

		return $state['generation'] ?? 0;
	}

	/**
	 * Returns an opaque fingerprint for byte-for-byte state comparisons.
	 *
	 * Callers compare this value only and must not include its literal in
	 * assertion output or evidence.
	 *
	 * @since 0.1.0
	 *
	 * @return string The opaque state fingerprint.
	 */
	public static function stateFingerprint(): string {
		return ProofStateFingerprint::forNetworkOption( self::STORE_OPTION );
	}

	/**
	 * Clears disposable guard state between integration tests.
	 *
	 * @since 0.1.0
	 */
	public static function resetProof(): void {
		delete_network_option( null, self::STORE_OPTION );
	}

	/**
	 * Reads validated disposable explicit-key guard state.
	 *
	 * @since 0.1.0
	 *
	 * @return array{accepted_fingerprint: string, generation: int, adoption_count: int}|null The guard state.
	 */
	private static function state(): ?array {
		$state = get_network_option( null, self::STORE_OPTION, null );

		if (
			! is_array( $state )
			|| ! is_string( $state['accepted_fingerprint'] ?? null )
			|| ! is_int( $state['generation'] ?? null )
			|| ! is_int( $state['adoption_count'] ?? null )
		) {
			return null;
		}

		return array(
			'accepted_fingerprint' => $state['accepted_fingerprint'],
			'generation'           => $state['generation'],
			'adoption_count'       => $state['adoption_count'],
		);
	}
}
