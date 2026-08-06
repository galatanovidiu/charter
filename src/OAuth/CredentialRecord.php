<?php
/**
 * Persisted OAuth credential record.
 *
 * @package GalatanOvidiu\Charter
 */

declare(strict_types=1);

namespace GalatanOvidiu\Charter\OAuth;

/**
 * Carries validated non-secret bindings loaded by digest.
 *
 * @since 0.1.0
 */
final class CredentialRecord {

	/**
	 * Creates a persisted credential value.
	 *
	 * @since 0.1.0
	 *
	 * @param int         $id            Database identifier.
	 * @param string      $type          Credential type.
	 * @param string      $issuer        Exact issuer.
	 * @param string      $resourceIdentifier Exact resource.
	 * @param string      $clientId      Exact client identifier.
	 * @param string      $redirectUri   Exact redirect URI.
	 * @param int         $userId        Represented WordPress user.
	 * @param string      $scope         Canonical scope string.
	 * @param string      $codeChallenge S256 challenge when applicable.
	 * @param string|null $requestState  Authorization state when applicable.
	 * @param int         $expiresAt     Absolute expiry timestamp.
	 * @param int|null    $consumedAt    Consumption or revocation timestamp.
	 * @param int|null    $grantId       Owning grant when authority exists.
	 * @param int|null    $parentId      Prior refresh member when applicable.
	 * @param bool        $continuingAccess Whether continuing access was approved.
	 */
	public function __construct(
		private readonly int $id,
		private readonly string $type,
		private readonly string $issuer,
		private readonly string $resourceIdentifier,
		private readonly string $clientId,
		private readonly string $redirectUri,
		private readonly int $userId,
		private readonly string $scope,
		private readonly string $codeChallenge,
		private readonly ?string $requestState,
		private readonly int $expiresAt,
		private readonly ?int $consumedAt,
		private readonly ?int $grantId = null,
		private readonly ?int $parentId = null,
		private readonly bool $continuingAccess = false
	) {
	}

	/**
	 * Returns the database identifier.
	 *
	 * @since 0.1.0
	 */
	public function id(): int {
		return $this->id;
	}

	/**
	 * Returns the credential type.
	 *
	 * @since 0.1.0
	 */
	public function type(): string {
		return $this->type;
	}

	/**
	 * Returns the exact issuer.
	 *
	 * @since 0.1.0
	 */
	public function issuer(): string {
		return $this->issuer;
	}

	/**
	 * Returns the exact resource.
	 *
	 * @since 0.1.0
	 */
	public function resource(): string {
		return $this->resourceIdentifier;
	}

	/**
	 * Returns the exact client identifier.
	 *
	 * @since 0.1.0
	 */
	public function clientId(): string {
		return $this->clientId;
	}

	/**
	 * Returns the exact redirect URI.
	 *
	 * @since 0.1.0
	 */
	public function redirectUri(): string {
		return $this->redirectUri;
	}

	/**
	 * Returns the represented WordPress user identifier.
	 *
	 * @since 0.1.0
	 */
	public function userId(): int {
		return $this->userId;
	}

	/**
	 * Returns the canonical scope string.
	 *
	 * @since 0.1.0
	 */
	public function scope(): string {
		return $this->scope;
	}

	/**
	 * Returns the S256 code challenge when applicable.
	 *
	 * @since 0.1.0
	 */
	public function codeChallenge(): string {
		return $this->codeChallenge;
	}

	/**
	 * Returns authorization state when applicable.
	 *
	 * @since 0.1.0
	 */
	public function requestState(): ?string {
		return $this->requestState;
	}

	/**
	 * Returns the absolute expiry timestamp.
	 *
	 * @since 0.1.0
	 */
	public function expiresAt(): int {
		return $this->expiresAt;
	}

	/**
	 * Returns the owning grant identifier when authority has been approved.
	 *
	 * @since 0.1.0
	 */
	public function grantId(): ?int {
		return $this->grantId;
	}

	/**
	 * Returns the prior refresh member identifier when applicable.
	 *
	 * @since 0.1.0
	 */
	public function parentId(): ?int {
		return $this->parentId;
	}

	/**
	 * Reports whether the user approved continuing access.
	 *
	 * @since 0.1.0
	 */
	public function continuingAccess(): bool {
		return $this->continuingAccess;
	}

	/**
	 * Returns the single-use consumption or revocation timestamp.
	 *
	 * @since 0.1.0
	 */
	public function consumedAt(): ?int {
		return $this->consumedAt;
	}

	/**
	 * Reports whether the credential is unconsumed and unexpired.
	 *
	 * @since 0.1.0
	 *
	 * @param int $timestamp Current Unix timestamp.
	 */
	public function isActiveAt( int $timestamp ): bool {
		return null === $this->consumedAt && $timestamp < $this->expiresAt;
	}
}
