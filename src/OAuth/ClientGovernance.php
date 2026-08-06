<?php
/**
 * Site-administrator OAuth client governance.
 *
 * @package GalatanOvidiu\Charter
 */

declare(strict_types=1);

namespace GalatanOvidiu\Charter\OAuth;

use GalatanOvidiu\Charter\Security\AuditLog;

/**
 * Blocks or deletes a client before cascading grant revocation.
 *
 * @since 0.1.0
 */
final class ClientGovernance {

	/**
	 * Creates site client governance.
	 *
	 * @param ClientRegistry              $clients Client registry.
	 * @param CredentialStore             $credentials Grant persistence.
	 * @param AuditLog                    $audit Security event ledger.
	 * @param ClientMetadataSnapshotStore $snapshots Reusable remote metadata.
	 */
	public function __construct(
		private readonly ClientRegistry $clients,
		private readonly CredentialStore $credentials,
		private readonly AuditLog $audit,
		private readonly ClientMetadataSnapshotStore $snapshots
	) {
	}

	/**
	 * Blocks future and existing credential use and revokes all active grants.
	 *
	 * @param string $issuer Exact issuer.
	 * @param string $clientId Exact client identifier.
	 * @param int    $actorUserId Acting administrator.
	 * @param int    $timestamp Current timestamp.
	 */
	public function block( string $issuer, string $clientId, int $actorUserId, int $timestamp ): bool {
		if ( ! $this->clients->block( $issuer, $clientId, $timestamp ) ) {
			return false;
		}
		$this->credentials->revokeAllGrantsForClient( $issuer, $clientId, $timestamp, 'administrator_client_block' );
		$this->discardSnapshot( $issuer, $clientId );
		$this->audit->record( $issuer, 'client_blocked', 'success', 'administrator_action', $actorUserId, null, $clientId, null, $timestamp );

		return true;
	}

	/**
	 * Tombstones the registration, erases its secret metadata, and revokes grants.
	 *
	 * @param string $issuer Exact issuer.
	 * @param string $clientId Exact client identifier.
	 * @param int    $actorUserId Acting administrator.
	 * @param int    $timestamp Current timestamp.
	 */
	public function delete( string $issuer, string $clientId, int $actorUserId, int $timestamp ): bool {
		if ( ! $this->clients->delete( $issuer, $clientId, $timestamp ) ) {
			return false;
		}
		$this->credentials->revokeAllGrantsForClient( $issuer, $clientId, $timestamp, 'administrator_client_delete' );
		$this->discardSnapshot( $issuer, $clientId );
		$this->audit->record( $issuer, 'client_deleted', 'success', 'administrator_action', $actorUserId, null, $clientId, null, $timestamp );

		return true;
	}

	/**
	 * Removes one abandoned dynamic registration only when no active grant remains.
	 *
	 * @param string $issuer Exact issuer.
	 * @param string $clientId Exact client identifier.
	 * @param int    $timestamp Current timestamp.
	 */
	public function deleteAbandoned( string $issuer, string $clientId, int $timestamp ): bool {
		if ( array() !== $this->credentials->listActiveGrantsForClient( $issuer, $clientId ) ) {
			return false;
		}
		if ( ! $this->clients->delete( $issuer, $clientId, $timestamp ) ) {
			return false;
		}
		$this->audit->record( $issuer, 'client_deleted', 'success', 'abandoned_registration_cleanup', null, null, $clientId, null, $timestamp );

		return true;
	}

	/**
	 * Discards reusable remote metadata after governance.
	 *
	 * @param string $issuer Exact issuer.
	 * @param string $clientId Exact client identifier.
	 */
	private function discardSnapshot( string $issuer, string $clientId ): void {
		try {
			$this->snapshots->delete( $issuer, $clientId );
		} catch ( \RuntimeException ) {
			// The terminal registry state remains authoritative and fail-closed.
			return;
		}
	}
}
