<?php
/**
 * Disposable Slice 0 proof-credential seam.
 *
 * @package GalatanOvidiu\Charter
 */

declare(strict_types=1);

namespace GalatanOvidiu\Charter\Tests\Prototype\Multisite;

/**
 * Stores minimal credentials for issuer/resource isolation evidence only.
 *
 * This deliberately does not model a token format, digest, grant, or durable
 * credential schema.
 *
 * @since 0.1.0
 */
final class ProofCredentialStore {

	/**
	 * Disposable network option used by the credential proof.
	 *
	 * @since 0.1.0
	 *
	 * @var string
	 */
	private const STORE_OPTION = 'charter_slice0_proof_credentials';

	/**
	 * Stores one proof credential with exact issuer and resource bindings.
	 *
	 * @since 0.1.0
	 *
	 * @param string         $credential The opaque proof credential.
	 * @param IssuerIdentity $identity   The exact issuer identity.
	 * @param string         $resourceIdentifier The exact protected-resource identifier.
	 */
	public static function issue( string $credential, IssuerIdentity $identity, string $resourceIdentifier ): void {
		$records                = self::records();
		$records[ $credential ] = array(
			'issuer'   => $identity->issuer(),
			'resource' => $resourceIdentifier,
		);

		update_network_option( null, self::STORE_OPTION, $records );
	}

	/**
	 * Accepts a credential only for its exact enabled issuer and resource.
	 *
	 * @since 0.1.0
	 *
	 * @param string         $credential The presented proof credential.
	 * @param IssuerIdentity $identity   The explicitly addressed issuer.
	 * @param string         $resourceIdentifier The explicitly addressed resource.
	 * @return bool Whether the exact binding is accepted.
	 */
	public static function accepts( string $credential, IssuerIdentity $identity, string $resourceIdentifier ): bool {
		$record = self::records()[ $credential ] ?? null;

		return is_array( $record )
			&& SiteIssuerLifecycle::isEnabledForV1Operation( $identity )
			&& ( $record['issuer'] ?? null ) === $identity->issuer()
			&& ( $record['resource'] ?? null ) === $resourceIdentifier;
	}

	/**
	 * Clears all disposable proof credentials between integration tests.
	 *
	 * @since 0.1.0
	 */
	public static function resetProof(): void {
		delete_network_option( null, self::STORE_OPTION );
	}

	/**
	 * Reads all proof-credential records.
	 *
	 * @since 0.1.0
	 *
	 * @return array<string, array{issuer: string, resource: string}> The proof records.
	 */
	private static function records(): array {
		$records = get_network_option( null, self::STORE_OPTION, array() );

		return is_array( $records ) ? $records : array();
	}
}
