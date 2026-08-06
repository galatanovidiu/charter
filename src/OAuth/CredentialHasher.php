<?php
/**
 * OAuth credential digest derivation.
 *
 * @package GalatanOvidiu\Charter
 */

declare(strict_types=1);

namespace GalatanOvidiu\Charter\OAuth;

use RuntimeException;

/**
 * Derives issuer- and type-separated one-way credential digests.
 *
 * @since 0.1.0
 */
final class CredentialHasher {

	private const WORDPRESS_SALT_SCHEMES = array(
		'auth',
		'secure_auth',
		'logged_in',
		'nonce',
	);

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
		$domainKey = hash_hmac(
			'sha256',
			self::frame( array( 'charter-oauth-v1', $issuer, $credentialType ) ),
			$this->rootKey(),
			true
		);

		return hash_hmac( 'sha256', $credential, $domainKey );
	}

	/**
	 * Returns current effective root material in memory only.
	 *
	 * @since 0.1.0
	 *
	 * @throws RuntimeException When an explicit key is invalid.
	 */
	private function rootKey(): string {
		if ( defined( 'CHARTER_SECRET_KEY' ) ) {
			$explicitKey = constant( 'CHARTER_SECRET_KEY' );
			if ( ! is_string( $explicitKey ) || '' === $explicitKey ) {
				throw new RuntimeException( 'charter_secret_key_invalid' );
			}

			return $explicitKey;
		}

		$values = array();
		foreach ( self::WORDPRESS_SALT_SCHEMES as $scheme ) {
			$values[] = wp_salt( $scheme );
		}

		return self::frame( $values );
	}

	/**
	 * Frames variable-length values without delimiter ambiguity.
	 *
	 * @since 0.1.0
	 *
	 * @param array<string> $values Values to frame.
	 */
	private static function frame( array $values ): string {
		$framed = '';
		foreach ( $values as $value ) {
			$framed .= strlen( $value ) . ':' . $value;
		}

		return $framed;
	}
}
