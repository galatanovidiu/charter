<?php
/**
 * Network control over isolated site issuers.
 *
 * @package GalatanOvidiu\Charter
 */

declare(strict_types=1);

namespace GalatanOvidiu\Charter\Admin;

use GalatanOvidiu\Charter\Http\MetadataController;
use GalatanOvidiu\Charter\OAuth\AccessPolicyProvider;
use GalatanOvidiu\Charter\OAuth\CredentialStore;
use GalatanOvidiu\Charter\OAuth\EmergencyContainment;
use GalatanOvidiu\Charter\OAuth\GrantGovernance;
use GalatanOvidiu\Charter\OAuth\GrantRecord;
use GalatanOvidiu\Charter\Schema;
use GalatanOvidiu\Charter\Security\AuditLog;
use GalatanOvidiu\Charter\Site\NetworkActivation;
use GalatanOvidiu\Charter\Site\SiteOrchestrator;
use GalatanOvidiu\Charter\Site\SiteState;
use Throwable;

/**
 * Executes one operation at a time inside one selected site's own boundary.
 *
 * @since 0.1.0
 */
final class NetworkSiteControl {

	/**
	 * Creates the site-scoped network control service.
	 *
	 * @param SiteState            $siteState Current switched-site lifecycle.
	 * @param CredentialStore      $credentials Current switched-site credentials.
	 * @param GrantGovernance      $grantGovernance Current switched-site grant governance.
	 * @param AuditLog             $audit Current switched-site security ledger.
	 * @param EmergencyContainment $containment Current switched-site emergency mode.
	 */
	public function __construct(
		private readonly SiteState $siteState,
		private readonly CredentialStore $credentials,
		private readonly GrantGovernance $grantGovernance,
		private readonly AuditLog $audit,
		private readonly EmergencyContainment $containment
	) {
	}

	/**
	 * Inspects one selected site's isolated OAuth state without initializing it.
	 *
	 * @param int $siteId Selected WordPress site identifier.
	 * @param int $grantLimit Maximum grants returned.
	 * @param int $grantOffset Grant pagination offset.
	 */
	public function inspect( int $siteId, int $grantLimit = 50, int $grantOffset = 0 ): ?NetworkSiteSnapshot {
		if ( ! SiteOrchestrator::isOperableSite( $siteId, true ) ) {
			return null;
		}

		$grantLimit  = max( 1, min( 50, $grantLimit ) );
		$grantOffset = max( 0, $grantOffset );

		return SiteOrchestrator::withinSite(
			$siteId,
			function () use ( $siteId, $grantLimit, $grantOffset ): NetworkSiteSnapshot {
				$identity     = $this->siteState->identity();
				$storageReady = Schema::isInstalled();
				$grantCount   = 0;
				$grants       = array();
				$events       = array();

				if ( null !== $identity && $storageReady ) {
					$grantCount = $this->credentials->countActiveGrantsForIssuer( $identity->issuer() );
					$grants     = $this->credentials->listActiveGrantsForIssuer( $identity->issuer(), $grantLimit, $grantOffset );
					$events     = $this->audit->listForIssuer( $identity->issuer(), 50 );
				}

				return new NetworkSiteSnapshot( $siteId, $this->siteState->state(), $identity, $storageReady, $grantCount, $grants, $events, $this->containment->snapshot() );
			}
		);
	}

	/**
	 * Prepares one explicitly selected Available site.
	 *
	 * @param int $siteId Selected WordPress site identifier.
	 * @param int $actorUserId Acting network administrator.
	 * @param int $timestamp Current Unix timestamp.
	 */
	public function prepare( int $siteId, int $actorUserId, int $timestamp ): bool {
		if ( $actorUserId <= 0 || ! SiteOrchestrator::isOperableSite( $siteId, true ) ) {
			return false;
		}

		return true === SiteOrchestrator::withinSite(
			$siteId,
			function () use ( $actorUserId, $timestamp ): bool {
				if ( SiteState::AVAILABLE !== $this->siteState->state() ) {
					return false;
				}

				Schema::install();
				if ( ! $this->siteState->prepareCurrentSite() ) {
					return false;
				}
				$identity = $this->siteState->identity();
				if ( null === $identity ) {
					return false;
				}

				( new MetadataController( $this->siteState, new AccessPolicyProvider(), $this->containment ) )->registerRewriteRules();
				flush_rewrite_rules( false );
				$this->audit->record( $identity->issuer(), 'site_prepared', 'success', 'network_administrator_preparation', $actorUserId, null, null, null, $timestamp );

				return true;
			}
		);
	}

	/**
	 * Enables one exactly identified Prepared site after operator verification.
	 *
	 * @param int    $siteId Selected WordPress site identifier.
	 * @param string $expectedIssuer Exact issuer confirmed by the operator.
	 * @param int    $actorUserId Acting network administrator.
	 * @param int    $timestamp Current Unix timestamp.
	 */
	public function enable( int $siteId, string $expectedIssuer, int $actorUserId, int $timestamp ): bool {
		if ( '' === $expectedIssuer || $actorUserId <= 0 || ! SiteOrchestrator::isOperableSite( $siteId, true ) ) {
			return false;
		}

		return true === SiteOrchestrator::withinSite(
			$siteId,
			function () use ( $expectedIssuer, $actorUserId, $timestamp ): bool {
				$identity = $this->siteState->identity();
				if ( SiteState::PREPARED !== $this->siteState->state() || null === $identity || ! hash_equals( $identity->issuer(), $expectedIssuer ) ) {
					return false;
				}

				if ( ! $this->siteState->recordDiscoveryVerification( $expectedIssuer ) || ! $this->siteState->enable( $expectedIssuer ) ) {
					return false;
				}

				$this->audit->record( $expectedIssuer, 'site_enabled', 'success', 'network_administrator_enablement', $actorUserId, null, null, null, $timestamp );

				return true;
			}
		);
	}

	/**
	 * Revokes one exact grant inside one selected site.
	 *
	 * @param int $siteId Selected WordPress site identifier.
	 * @param int $grantId Selected site-local grant identifier.
	 * @param int $actorUserId Acting network administrator.
	 * @param int $timestamp Current Unix timestamp.
	 */
	public function revokeGrant( int $siteId, int $grantId, int $actorUserId, int $timestamp ): ?GrantRecord {
		if ( $grantId <= 0 || $actorUserId <= 0 || ! SiteOrchestrator::isOperableSite( $siteId, true ) ) {
			return null;
		}

		$result = SiteOrchestrator::withinSite(
			$siteId,
			function () use ( $grantId, $actorUserId, $timestamp ): ?GrantRecord {
				$identity = $this->siteState->identity();
				if ( null === $identity || ! Schema::isInstalled() ) {
					return null;
				}

				return $this->grantGovernance->revokeByNetworkAdministrator( $identity->issuer(), $grantId, $actorUserId, $timestamp );
			}
		);

		return $result instanceof GrantRecord ? $result : null;
	}

	/**
	 * Revokes every active grant inside one selected site issuer.
	 *
	 * @param int $siteId Selected WordPress site identifier.
	 * @param int $actorUserId Acting network administrator.
	 * @param int $timestamp Current Unix timestamp.
	 * @return array<GrantRecord> Exact grants closed by the action.
	 */
	public function revokeAllGrants( int $siteId, int $actorUserId, int $timestamp ): array {
		if ( $actorUserId <= 0 || ! SiteOrchestrator::isOperableSite( $siteId, true ) ) {
			return array();
		}

		$result = SiteOrchestrator::withinSite(
			$siteId,
			function () use ( $actorUserId, $timestamp ): array {
				$identity = $this->siteState->identity();
				if ( null === $identity || ! Schema::isInstalled() ) {
					return array();
				}

				return $this->grantGovernance->revokeAllByNetworkAdministrator( $identity->issuer(), $actorUserId, $timestamp );
			}
		);

		return $result;
	}

	/**
	 * Changes one exact selected issuer's reversible containment mode.
	 *
	 * @param int    $siteId Selected WordPress site identifier.
	 * @param string $expectedIssuer Exact issuer bound to the administrator action.
	 * @param string $mode Target containment mode.
	 * @param int    $actorUserId Acting network administrator.
	 * @param int    $timestamp Current Unix timestamp.
	 */
	public function transitionContainment( int $siteId, string $expectedIssuer, string $mode, int $actorUserId, int $timestamp ): bool {
		if ( '' === $expectedIssuer || $actorUserId <= 0 || ! SiteOrchestrator::isOperableSite( $siteId, true ) ) {
			return false;
		}

		try {
			return true === SiteOrchestrator::withinSite(
				$siteId,
				fn (): bool => $this->containment->transition(
					$mode,
					EmergencyContainment::ACTOR_NETWORK_ADMIN,
					$actorUserId,
					$timestamp,
					$expectedIssuer
				)
			);
		} catch ( Throwable ) {
			return false;
		}
	}

	/**
	 * Reports the selected site's audit-reconciliation state without reading the
	 * audit table that may have caused the pending state.
	 *
	 * @param int $siteId Selected WordPress site identifier.
	 */
	public function containmentAuditPending( int $siteId ): ?bool {
		if ( ! SiteOrchestrator::isOperableSite( $siteId, true ) ) {
			return null;
		}

		try {
			return true === SiteOrchestrator::withinSite(
				$siteId,
				fn (): bool => $this->containment->snapshot()['audit_pending']
			);
		} catch ( Throwable ) {
			return null;
		}
	}

	/**
	 * Applies one mode sequentially to every enabled issuer in this network.
	 *
	 * Available or Prepared sites are skipped because they expose no operational
	 * OAuth issuer to contain.
	 *
	 * @param string $mode Target containment mode.
	 * @param int    $actorUserId Acting network administrator.
	 * @param int    $timestamp Current Unix timestamp.
	 * @return array{changed:int,unchanged:int,skipped:int,pending:int,failed:int}
	 */
	public function transitionAllContainment( string $mode, int $actorUserId, int $timestamp ): array {
		$counts = array(
			'changed'   => 0,
			'unchanged' => 0,
			'skipped'   => 0,
			'pending'   => 0,
			'failed'    => 0,
		);
		if ( $actorUserId <= 0 || ! EmergencyContainment::isMode( $mode ) || ! NetworkActivation::isActive() ) {
			$counts['failed'] = 1;

			return $counts;
		}

		foreach ( SiteOrchestrator::liveCurrentNetworkSiteIds() as $siteId ) {
			try {
				$result = SiteOrchestrator::withinSite(
					$siteId,
					function () use ( $mode, $actorUserId, $timestamp ): string {
						$identity = $this->siteState->identity();
						if ( null === $identity || ! $this->siteState->isEnabled() ) {
							return 'skipped';
						}
						$before = $this->containment->mode();
						if ( ! $this->containment->transition( $mode, EmergencyContainment::ACTOR_NETWORK_ADMIN, $actorUserId, $timestamp, $identity->issuer() ) ) {
							return 'failed';
						}
						if ( $this->containment->snapshot()['audit_pending'] ) {
							return 'pending';
						}

						return $before === $mode ? 'unchanged' : 'changed';
					}
				);
			} catch ( Throwable ) {
				$result = 'failed';
			}
			++$counts[ $result ];
		}

		return $counts;
	}
}
