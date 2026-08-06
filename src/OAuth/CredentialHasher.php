<?php
/**
 * OAuth credential digest derivation.
 *
 * @package GalatanOvidiu\Charter
 */

declare(strict_types=1);

namespace GalatanOvidiu\Charter\OAuth;

/**
 * Derives issuer- and type-separated one-way credential digests.
 *
 * @since 0.1.0
 */
final class CredentialHasher {

	/**
	 * Creates the digest adapter over the shared key lifecycle.
	 *
	 * @param SigningKeyLifecycle $signingKeys Issuer-local key lifecycle.
	 */
	public function __construct( private readonly SigningKeyLifecycle $signingKeys ) {
	}

	/**
	 * Produces one credential digest without persisting key material.
	 *
	 * @since 0.1.0
	 *
	 * @param string $issuer         Exact issuer.
	 * @param string $credentialType Credential domain.
	 * @param string $credential     Presented opaque credential.
	 */
	public function digest( string $issuer, string $credentialType, string $credential ): string {
		return $this->signingKeys->digest( $issuer, $credentialType, $credential );
	}
}
