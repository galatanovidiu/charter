<?php
/**
 * OAuth client registry projection.
 *
 * @package GalatanOvidiu\Charter
 */

declare(strict_types=1);

namespace GalatanOvidiu\Charter\OAuth;

/**
 * Carries non-secret client lifecycle facts for administration and cleanup.
 *
 * @since 0.1.0
 */
final class ClientRegistrationRecord {

	/**
	 * Creates one validated registry projection.
	 *
	 * @param string        $issuer Exact issuer.
	 * @param string        $clientId Exact client identifier.
	 * @param string        $name Display name.
	 * @param array<string> $redirectUris Exact registered redirects.
	 * @param string        $status Lifecycle status.
	 * @param string        $source Onboarding source.
	 * @param string        $authenticationMethod Token authentication method.
	 * @param array<string> $grantTypes Supported grants.
	 * @param string        $metadataFingerprint Security metadata fingerprint.
	 * @param int           $createdAt Creation timestamp.
	 * @param int           $lastActivityAt Last protocol activity timestamp.
	 * @param int|null      $authorizedAt First completed authorization timestamp.
	 */
	public function __construct(
		private readonly string $issuer,
		private readonly string $clientId,
		private readonly string $name,
		private readonly array $redirectUris,
		private readonly string $status,
		private readonly string $source,
		private readonly string $authenticationMethod,
		private readonly array $grantTypes,
		private readonly string $metadataFingerprint,
		private readonly int $createdAt,
		private readonly int $lastActivityAt,
		private readonly ?int $authorizedAt
	) {
	}

	/** Returns the exact issuer. */
	public function issuer(): string {
		return $this->issuer;
	}

	/** Returns the exact client identifier. */
	public function clientId(): string {
		return $this->clientId;
	}

	/** Returns the display name. */
	public function name(): string {
		return $this->name;
	}

	/**
	 * Returns the exact registered redirects.
	 *
	 * @return array<string>
	 */
	public function redirectUris(): array {
		return $this->redirectUris;
	}

	/** Returns the lifecycle status. */
	public function status(): string {
		return $this->status;
	}

	/** Returns the onboarding source. */
	public function source(): string {
		return $this->source;
	}

	/** Returns the token-endpoint authentication method. */
	public function authenticationMethod(): string {
		return $this->authenticationMethod;
	}

	/**
	 * Returns supported grant types.
	 *
	 * @return array<string>
	 */
	public function grantTypes(): array {
		return $this->grantTypes;
	}

	/** Returns the security metadata fingerprint. */
	public function metadataFingerprint(): string {
		return $this->metadataFingerprint;
	}

	/** Returns the creation timestamp. */
	public function createdAt(): int {
		return $this->createdAt;
	}

	/** Returns the last protocol activity timestamp. */
	public function lastActivityAt(): int {
		return $this->lastActivityAt;
	}

	/** Returns the first authorization timestamp when present. */
	public function authorizedAt(): ?int {
		return $this->authorizedAt;
	}
}
