<?php
/**
 * Site-administrator OAuth grant governance.
 *
 * @package GalatanOvidiu\Charter
 */

declare(strict_types=1);

namespace GalatanOvidiu\Charter\OAuth;

use GalatanOvidiu\Charter\Security\AuditLog;

/**
 * Closes issuer-owned grants and records only non-secret authorization context.
 *
 * @since 0.1.0
 */
final class GrantGovernance {

	/**
	 * Creates site grant governance.
	 *
	 * @param CredentialStore $credentials Authoritative grant persistence.
	 * @param AuditLog        $audit Secret-free event ledger.
	 */
	public function __construct(
		private readonly CredentialStore $credentials,
		private readonly AuditLog $audit
	) {
	}

	/**
	 * Revokes one exact grant inside one exact site issuer.
	 *
	 * @param string $issuer Exact current issuer.
	 * @param int    $grantId Grant identifier.
	 * @param int    $actorUserId Acting site administrator.
	 * @param int    $timestamp Current Unix timestamp.
	 * @return GrantRecord|null Exact closed grant, or null outside the boundary.
	 */
	public function revoke( string $issuer, int $grantId, int $actorUserId, int $timestamp ): ?GrantRecord {
		return $this->revokeWithReason( $issuer, $grantId, $actorUserId, $timestamp, 'administrator_grant_revocation' );
	}

	/**
	 * Revokes one grant for a network administrator operating inside its site.
	 *
	 * @param string $issuer Exact selected site issuer.
	 * @param int    $grantId Site-local grant identifier.
	 * @param int    $actorUserId Acting network administrator.
	 * @param int    $timestamp Current Unix timestamp.
	 */
	public function revokeByNetworkAdministrator( string $issuer, int $grantId, int $actorUserId, int $timestamp ): ?GrantRecord {
		return $this->revokeWithReason( $issuer, $grantId, $actorUserId, $timestamp, 'network_administrator_grant_revocation' );
	}

	/**
	 * Revokes every active authorization inside one exact site issuer.
	 *
	 * @param string $issuer Exact current issuer.
	 * @param int    $actorUserId Acting site administrator.
	 * @param int    $timestamp Current Unix timestamp.
	 * @return array<GrantRecord> Exact grants closed by the action.
	 */
	public function revokeAll( string $issuer, int $actorUserId, int $timestamp ): array {
		return $this->revokeAllWithReason( $issuer, $actorUserId, $timestamp, 'administrator_site_revocation' );
	}

	/**
	 * Revokes all grants for a network administrator inside one selected site.
	 *
	 * @param string $issuer Exact selected site issuer.
	 * @param int    $actorUserId Acting network administrator.
	 * @param int    $timestamp Current Unix timestamp.
	 * @return array<GrantRecord> Exact grants closed by the action.
	 */
	public function revokeAllByNetworkAdministrator( string $issuer, int $actorUserId, int $timestamp ): array {
		return $this->revokeAllWithReason( $issuer, $actorUserId, $timestamp, 'network_administrator_site_revocation' );
	}

	/**
	 * Revokes one exact grant with a fixed administrator provenance.
	 *
	 * @param string $issuer Exact site issuer.
	 * @param int    $grantId Site-local grant identifier.
	 * @param int    $actorUserId Acting administrator.
	 * @param int    $timestamp Current Unix timestamp.
	 * @param string $reason Stable revocation reason.
	 */
	private function revokeWithReason( string $issuer, int $grantId, int $actorUserId, int $timestamp, string $reason ): ?GrantRecord {
		if ( $actorUserId <= 0 ) {
			return null;
		}
		$grant = $this->credentials->revokeGrantForIssuer( $issuer, $grantId, $timestamp, $reason );
		if ( null === $grant ) {
			return null;
		}

		$this->audit->record(
			$issuer,
			'grant_revoked',
			'success',
			$reason,
			$actorUserId,
			$grant->userId(),
			$grant->clientId(),
			null,
			$timestamp,
			$grant->resource(),
			$grant->scope()
		);

		return $grant;
	}

	/**
	 * Revokes every active grant with a fixed administrator provenance.
	 *
	 * @param string $issuer Exact site issuer.
	 * @param int    $actorUserId Acting administrator.
	 * @param int    $timestamp Current Unix timestamp.
	 * @param string $reason Stable revocation reason.
	 * @return array<GrantRecord> Exact grants closed by the action.
	 */
	private function revokeAllWithReason( string $issuer, int $actorUserId, int $timestamp, string $reason ): array {
		if ( $actorUserId <= 0 ) {
			return array();
		}
		$grants = $this->credentials->revokeAllGrantsForIssuer( $issuer, $timestamp, $reason );
		if ( array() === $grants ) {
			return array();
		}

		$this->audit->record( $issuer, 'site_grants_revoked', 'success', $reason, $actorUserId, null, null, null, $timestamp );

		return $grants;
	}
}
