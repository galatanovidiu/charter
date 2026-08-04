<?php
/**
 * Disposable Slice 0 non-credential preservation sentinels.
 *
 * @package GalatanOvidiu\Charter
 */

declare(strict_types=1);

namespace GalatanOvidiu\Charter\Tests\Prototype\Multisite;

/**
 * Stores minimal registration, consent, and non-secret audit sentinels.
 *
 * These values exist only to prove preservation across root-key transitions.
 * They are not proposed production entities, records, or audit formats.
 *
 * @since 0.1.0
 */
final class RootKeyProofState {

	/**
	 * Disposable network option used by non-credential proof state.
	 *
	 * @since 0.1.0
	 *
	 * @var string
	 */
	private const STORE_OPTION = 'charter_slice0_root_key_sentinels';

	/**
	 * Creates fixed non-secret preservation sentinels for one exact issuer.
	 *
	 * @since 0.1.0
	 *
	 * @param string $issuer Exact opaque issuer identifier.
	 */
	public static function seedSentinels( string $issuer ): void {
		if ( '' === $issuer ) {
			return;
		}

		$records            = self::records();
		$records[ $issuer ] = self::sentinelRecord();

		update_network_option( null, self::STORE_OPTION, $records );
	}

	/**
	 * Reports whether one issuer retains all fixed sentinels unchanged.
	 *
	 * @since 0.1.0
	 *
	 * @param string $issuer Exact opaque issuer identifier.
	 * @return bool Whether every sentinel remains intact.
	 */
	public static function sentinelsIntactFor( string $issuer ): bool {
		$record = self::records()[ $issuer ] ?? null;

		return self::sentinelRecord() === $record;
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
	 * Returns counts of non-secret sentinels without their stored values.
	 *
	 * @since 0.1.0
	 *
	 * @return array{issuer_count: int, registration_count: int, consent_count: int, audit_count: int} Sanitized evidence.
	 */
	public static function sanitizedEvidence(): array {
		$issuerCount = count( self::records() );

		return array(
			'issuer_count'       => $issuerCount,
			'registration_count' => $issuerCount,
			'consent_count'      => $issuerCount,
			'audit_count'        => $issuerCount,
		);
	}

	/**
	 * Clears all disposable sentinels between integration tests.
	 *
	 * @since 0.1.0
	 */
	public static function resetProof(): void {
		delete_network_option( null, self::STORE_OPTION );
	}

	/**
	 * Returns the fixed non-secret sentinel record.
	 *
	 * @since 0.1.0
	 *
	 * @return array{registration: string, consent: string, audit: string} The fixed sentinels.
	 */
	private static function sentinelRecord(): array {
		return array(
			'registration' => 'registration-sentinel',
			'consent'      => 'consent-sentinel',
			'audit'        => 'non-secret-audit-sentinel',
		);
	}

	/**
	 * Reads validated non-credential sentinel records.
	 *
	 * @since 0.1.0
	 *
	 * @return array<string, array{registration: string, consent: string, audit: string}> The valid sentinel records.
	 */
	private static function records(): array {
		$records = get_network_option( null, self::STORE_OPTION, array() );

		if ( ! is_array( $records ) ) {
			return array();
		}

		$validRecords = array();

		foreach ( $records as $issuer => $record ) {
			if (
				! is_string( $issuer )
				|| ! is_array( $record )
				|| ! is_string( $record['registration'] ?? null )
				|| ! is_string( $record['consent'] ?? null )
				|| ! is_string( $record['audit'] ?? null )
			) {
				continue;
			}

			$validRecords[ $issuer ] = array(
				'registration' => $record['registration'],
				'consent'      => $record['consent'],
				'audit'        => $record['audit'],
			);
		}

		return $validRecords;
	}
}
