<?php
/**
 * Validated disposable CIMD metadata value.
 *
 * @package GalatanOvidiu\Charter
 */

declare(strict_types=1);

namespace GalatanOvidiu\Charter\Tests\Prototype\CimdOutboundSafety;

/**
 * Exposes only metadata that is authoritative for authorization.
 *
 * @since 0.1.0
 */
final class ValidatedMetadata {

	/**
	 * Creates an authoritative metadata projection.
	 *
	 * @since 0.1.0
	 *
	 * @param string $clientId                Exact client identity.
	 * @param string $clientName              Bounded display name.
	 * @param array  $redirectUris            Exact registered redirects.
	 * @param string $tokenEndpointAuthMethod Accepted authentication method.
	 * @param string $fingerprint             Document fingerprint.
	 * @phpstan-param list<string> $redirectUris
	 */
	public function __construct(
		private string $clientId,
		private string $clientName,
		private array $redirectUris,
		private string $tokenEndpointAuthMethod,
		private string $fingerprint
	) {
	}

	/**
	 * Returns the exact client identity.
	 *
	 * @since 0.1.0
	 *
	 * @return string Exact client identity.
	 */
	public function clientId(): string {
		return $this->clientId;
	}

	/**
	 * Returns the bounded client display name.
	 *
	 * @since 0.1.0
	 *
	 * @return string Bounded client display name.
	 */
	public function clientName(): string {
		return $this->clientName;
	}

	/**
	 * Returns the exact registered redirects.
	 *
	 * @since 0.1.0
	 *
	 * @return list<string> Exact registered redirects.
	 */
	public function redirectUris(): array {
		return $this->redirectUris;
	}

	/**
	 * Returns the accepted authentication method.
	 *
	 * @since 0.1.0
	 *
	 * @return string Accepted authentication method.
	 */
	public function tokenEndpointAuthMethod(): string {
		return $this->tokenEndpointAuthMethod;
	}

	/**
	 * Returns the non-secret document fingerprint.
	 *
	 * @since 0.1.0
	 *
	 * @return string Document fingerprint.
	 */
	public function fingerprint(): string {
		return $this->fingerprint;
	}

	/**
	 * Checks exact redirect membership.
	 *
	 * @param string $redirectUri Requested redirect.
	 * @return bool Whether the redirect is registered exactly.
	 */
	public function hasRedirect( string $redirectUri ): bool {
		return in_array( $redirectUri, $this->redirectUris, true );
	}
}
