<?php
/**
 * Persisted OAuth grant record.
 *
 * @package GalatanOvidiu\Charter
 */

declare(strict_types=1);

namespace GalatanOvidiu\Charter\OAuth;

/**
 * Carries one exact user-approved authorization relationship.
 *
 * @since 0.1.0
 */
final class GrantRecord {

	/**
	 * Creates a persisted grant value.
	 *
	 * @since 0.1.0
	 *
	 * @param int         $id Grant identifier.
	 * @param string      $issuer Exact issuer.
	 * @param string      $resourceIdentifier Exact resource.
	 * @param string      $clientId Exact client identifier.
	 * @param string      $redirectUri Approved redirect identity.
	 * @param int         $userId Represented WordPress user.
	 * @param string      $scope Approved protected-resource scopes.
	 * @param bool        $continuingAccess Whether refresh access was approved.
	 * @param string      $status Authoritative lifecycle status.
	 * @param int         $authorizedAt Initial authorization timestamp.
	 * @param int         $lastUsedAt Most recent credential issuance or refresh.
	 * @param int|null    $refreshAbsoluteExpiresAt Absolute refresh-family expiry.
	 * @param int|null    $refreshInactivityExpiresAt Refresh-family inactivity expiry.
	 * @param string      $clientMetadataFingerprint Approved client metadata binding.
	 * @param int|null    $revokedAt Terminal transition timestamp.
	 * @param string|null $revocationReason Stable non-secret terminal reason.
	 */
	public function __construct(
		private readonly int $id,
		private readonly string $issuer,
		private readonly string $resourceIdentifier,
		private readonly string $clientId,
		private readonly string $redirectUri,
		private readonly int $userId,
		private readonly string $scope,
		private readonly bool $continuingAccess,
		private readonly string $status,
		private readonly int $authorizedAt,
		private readonly int $lastUsedAt,
		private readonly ?int $refreshAbsoluteExpiresAt,
		private readonly ?int $refreshInactivityExpiresAt,
		private readonly string $clientMetadataFingerprint = '',
		private readonly ?int $revokedAt = null,
		private readonly ?string $revocationReason = null
	) {
	}

	/**
	 * Returns the grant identifier.
	 *
	 * @since 0.1.0
	 */
	public function id(): int {
		return $this->id;
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
	 * Returns the exact protected resource.
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
	 * Returns the approved redirect identity.
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
	 * Returns the approved protected-resource scope set.
	 *
	 * @since 0.1.0
	 */
	public function scope(): string {
		return $this->scope;
	}

	/**
	 * Reports whether continuing access was approved.
	 *
	 * @since 0.1.0
	 */
	public function continuingAccess(): bool {
		return $this->continuingAccess;
	}

	/**
	 * Returns the initial authorization timestamp.
	 *
	 * @since 0.1.0
	 */
	public function authorizedAt(): int {
		return $this->authorizedAt;
	}

	/**
	 * Returns the most recent grant activity timestamp.
	 *
	 * @since 0.1.0
	 */
	public function lastUsedAt(): int {
		return $this->lastUsedAt;
	}

	/**
	 * Returns the authoritative lifecycle status.
	 *
	 * @since 0.1.0
	 */
	public function status(): string {
		return $this->status;
	}

	/**
	 * Returns the immutable refresh-family absolute expiry.
	 *
	 * @since 0.1.0
	 */
	public function refreshAbsoluteExpiresAt(): ?int {
		return $this->refreshAbsoluteExpiresAt;
	}

	/** Returns the client metadata binding approved by the user. */
	public function clientMetadataFingerprint(): string {
		return $this->clientMetadataFingerprint;
	}

	/** Returns the terminal transition timestamp when retained. */
	public function revokedAt(): ?int {
		return $this->revokedAt;
	}

	/** Returns the stable non-secret terminal reason when retained. */
	public function revocationReason(): ?string {
		return $this->revocationReason;
	}

	/**
	 * Reports whether the grant and, when relevant, refresh family are current.
	 *
	 * @since 0.1.0
	 *
	 * @param int  $timestamp Current Unix timestamp.
	 * @param bool $requireContinuingAccess Whether refresh eligibility is required.
	 */
	public function isActiveAt( int $timestamp, bool $requireContinuingAccess = false ): bool {
		if ( 'active' !== $this->status ) {
			return false;
		}

		if ( ! $requireContinuingAccess ) {
			return true;
		}

		return $this->continuingAccess
			&& is_int( $this->refreshAbsoluteExpiresAt )
			&& is_int( $this->refreshInactivityExpiresAt )
			&& $timestamp < $this->refreshAbsoluteExpiresAt
			&& $timestamp < $this->refreshInactivityExpiresAt;
	}
}
