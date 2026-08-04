<?php
/**
 * Disposable Slice 0 digested proof-credential store.
 *
 * @package GalatanOvidiu\Charter
 */

declare(strict_types=1);

namespace GalatanOvidiu\Charter\Tests\Prototype\Multisite;

/**
 * Stores one-way proof digests with explicit credential bindings.
 *
 * The digest and option representations are disposable. This class does not
 * select a production credential algorithm, schema, repository, or wire form.
 *
 * @since 0.1.0
 */
final class DigestedProofCredentialStore {

	/**
	 * Disposable network option used by the root-key proof.
	 *
	 * @since 0.1.0
	 *
	 * @var string
	 */
	private const STORE_OPTION = 'charter_slice0_digested_proof_credentials';

	/**
	 * Stores one proof digest with exact issuer, resource, and type bindings.
	 *
	 * @since 0.1.0
	 *
	 * @param string                 $credential The opaque proof credential.
	 * @param EffectiveRootKeySource $source Current in-memory root snapshot.
	 * @param IssuerIdentity         $identity Explicit issuer and site locator.
	 * @param string                 $resourceIdentifier Exact protected-resource identifier.
	 * @param string                 $credentialType Named proof credential type.
	 * @return bool Whether the credential proof was stored.
	 */
	public static function issue(
		string $credential,
		EffectiveRootKeySource $source,
		IssuerIdentity $identity,
		string $resourceIdentifier,
		string $credentialType
	): bool {
		if (
			'' === $credential
			|| '' === $identity->issuer()
			|| '' === $resourceIdentifier
			|| '' === $credentialType
			|| ! SiteIssuerLifecycle::isEnabledForV1Operation( $identity )
			|| ! ExplicitKeyGuard::allowsCredentialOperations( $source )
		) {
			return false;
		}

		$digest             = self::credentialDigest( $credential, $source, $identity, $credentialType );
		$records            = self::records();
		$records[ $digest ] = array(
			'site_id'         => $identity->siteId(),
			'issuer'          => $identity->issuer(),
			'resource'        => $resourceIdentifier,
			'credential_type' => $credentialType,
		);

		update_network_option( null, self::STORE_OPTION, $records );

		return true;
	}

	/**
	 * Accepts a proof credential only in its exact explicit binding domain.
	 *
	 * @since 0.1.0
	 *
	 * @param string                 $credential The presented proof credential.
	 * @param EffectiveRootKeySource $source Current in-memory root snapshot.
	 * @param IssuerIdentity         $identity Explicit issuer and site locator.
	 * @param string                 $resourceIdentifier Exact protected-resource identifier.
	 * @param string                 $credentialType Named proof credential type.
	 * @return bool Whether the exact credential binding is accepted.
	 */
	public static function accepts(
		string $credential,
		EffectiveRootKeySource $source,
		IssuerIdentity $identity,
		string $resourceIdentifier,
		string $credentialType
	): bool {
		if (
			'' === $credential
			|| ! SiteIssuerLifecycle::isEnabledForV1Operation( $identity )
			|| ! ExplicitKeyGuard::allowsCredentialOperations( $source )
		) {
			return false;
		}

		$digest = self::credentialDigest( $credential, $source, $identity, $credentialType );
		$record = self::records()[ $digest ] ?? null;

		return is_array( $record )
			&& $record['site_id'] === $identity->siteId()
			&& $record['issuer'] === $identity->issuer()
			&& $record['resource'] === $resourceIdentifier
			&& $record['credential_type'] === $credentialType;
	}

	/**
	 * Removes every proof digest located by one deleted WordPress site.
	 *
	 * The site ID is cleanup data only. Credential acceptance remains bound to
	 * the exact issuer, resource, and credential-type strings.
	 *
	 * @since 0.1.0
	 *
	 * @param int $siteId The deleted non-identity WordPress site locator.
	 */
	public static function deleteForSite( int $siteId ): void {
		$records = self::records();

		foreach ( $records as $digest => $record ) {
			if ( $siteId === $record['site_id'] ) {
				unset( $records[ $digest ] );
			}
		}

		update_network_option( null, self::STORE_OPTION, $records );
	}

	/**
	 * Returns the number of valid persisted proof digests.
	 *
	 * @since 0.1.0
	 *
	 * @return int The record count.
	 */
	public static function recordCount(): int {
		return count( self::records() );
	}

	/**
	 * Returns sanitized bindings without a credential, root, key, or digest.
	 *
	 * @since 0.1.0
	 *
	 * @return array{record_count: int, records: list<array{site_id: int, issuer: string, resource: string, credential_type: string}>, digest_only: bool} Sanitized evidence.
	 */
	public static function sanitizedEvidence(): array {
		$stored  = get_network_option( null, self::STORE_OPTION, array() );
		$records = self::records();
		$visible = array();

		foreach ( $records as $record ) {
			$visible[] = $record;
		}

		return array(
			'record_count' => count( $records ),
			'records'      => $visible,
			'digest_only'  => is_array( $stored ) && $stored === $records,
		);
	}

	/**
	 * Checks persisted state for one forbidden value without returning state.
	 *
	 * @since 0.1.0
	 *
	 * @param string $forbiddenValue A value that must not be persisted.
	 * @return bool Whether persisted proof state contains the supplied value.
	 */
	public static function persistedStateContains( string $forbiddenValue ): bool {
		if ( '' === $forbiddenValue ) {
			return false;
		}

		$stored       = get_network_option( null, self::STORE_OPTION, array() );
		$encodedState = wp_json_encode( $stored );

		return is_string( $encodedState ) && str_contains( $encodedState, $forbiddenValue );
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
	 * Clears all disposable digested credentials between integration tests.
	 *
	 * @since 0.1.0
	 */
	public static function resetProof(): void {
		delete_network_option( null, self::STORE_OPTION );
	}

	/**
	 * Derives a proof digest in the current explicit-key generation, if any.
	 *
	 * Binding the disposable guard generation prevents a previously adopted
	 * key from making its earlier credentials reachable if it is adopted again.
	 * This is proof mechanics, not a production generation representation.
	 *
	 * @since 0.1.0
	 *
	 * @param string                 $credential The presented proof credential.
	 * @param EffectiveRootKeySource $source Current in-memory root snapshot.
	 * @param IssuerIdentity         $identity Explicit issuer and site locator.
	 * @param string                 $credentialType Named proof credential type.
	 * @return string The disposable one-way proof digest.
	 */
	private static function credentialDigest(
		string $credential,
		EffectiveRootKeySource $source,
		IssuerIdentity $identity,
		string $credentialType
	): string {
		$proofDomain = $credentialType;

		if ( $source->usesExplicitSnapshot() ) {
			$proofDomain .= ':explicit-generation:' . ExplicitKeyGuard::credentialGeneration();
		}

		return $source->credentialProofDigest( $identity->issuer(), $proofDomain, $credential );
	}

	/**
	 * Reads validated proof-digest records.
	 *
	 * @since 0.1.0
	 *
	 * @return array<string, array{site_id: int, issuer: string, resource: string, credential_type: string}> The valid proof records keyed by digest.
	 */
	private static function records(): array {
		$records = get_network_option( null, self::STORE_OPTION, array() );

		if ( ! is_array( $records ) ) {
			return array();
		}

		$validRecords = array();

		foreach ( $records as $digest => $record ) {
			if (
				! is_string( $digest )
				|| 1 !== preg_match( '/^[a-f0-9]{64}$/', $digest )
				|| ! is_array( $record )
				|| ! is_int( $record['site_id'] ?? null )
				|| ! is_string( $record['issuer'] ?? null )
				|| ! is_string( $record['resource'] ?? null )
				|| ! is_string( $record['credential_type'] ?? null )
			) {
				continue;
			}

			$validRecords[ $digest ] = array(
				'site_id'         => $record['site_id'],
				'issuer'          => $record['issuer'],
				'resource'        => $record['resource'],
				'credential_type' => $record['credential_type'],
			);
		}

		return $validRecords;
	}
}
