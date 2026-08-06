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
use GalatanOvidiu\Charter\OAuth\GrantGovernance;
use GalatanOvidiu\Charter\OAuth\GrantRecord;
use GalatanOvidiu\Charter\Schema;
use GalatanOvidiu\Charter\Security\AuditLog;
use GalatanOvidiu\Charter\Site\NetworkActivation;
use GalatanOvidiu\Charter\Site\SiteState;
use WP_Site;

/**
 * Executes one operation at a time inside one selected site's own boundary.
 *
 * @since 0.1.0
 */
final class NetworkSiteControl {

	/**
	 * Creates the site-scoped network control service.
	 *
	 * @param SiteState       $siteState Current switched-site lifecycle.
	 * @param CredentialStore $credentials Current switched-site credentials.
	 * @param GrantGovernance $grantGovernance Current switched-site grant governance.
	 * @param AuditLog        $audit Current switched-site security ledger.
	 */
	public function __construct(
		private readonly SiteState $siteState,
		private readonly CredentialStore $credentials,
		private readonly GrantGovernance $grantGovernance,
		private readonly AuditLog $audit
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
		if ( ! $this->isOperableSite( $siteId ) ) {
			return null;
		}

		$grantLimit  = max( 1, min( 50, $grantLimit ) );
		$grantOffset = max( 0, $grantOffset );

		return $this->withinSite(
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

				return new NetworkSiteSnapshot( $siteId, $this->siteState->state(), $identity, $storageReady, $grantCount, $grants, $events );
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
		if ( $actorUserId <= 0 || ! $this->isOperableSite( $siteId ) ) {
			return false;
		}

		return true === $this->withinSite(
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

				( new MetadataController( $this->siteState, new AccessPolicyProvider() ) )->registerRewriteRules();
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
		if ( '' === $expectedIssuer || $actorUserId <= 0 || ! $this->isOperableSite( $siteId ) ) {
			return false;
		}

		return true === $this->withinSite(
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
		if ( $grantId <= 0 || $actorUserId <= 0 || ! $this->isOperableSite( $siteId ) ) {
			return null;
		}

		$result = $this->withinSite(
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
		if ( $actorUserId <= 0 || ! $this->isOperableSite( $siteId ) ) {
			return array();
		}

		$result = $this->withinSite(
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
	 * Reports whether one active site belongs to the current network.
	 *
	 * @param int $siteId WordPress site identifier.
	 */
	private function isOperableSite( int $siteId ): bool {
		if ( $siteId <= 0 || ! NetworkActivation::isActive() ) {
			return false;
		}

		$site = get_site( $siteId );

		return $site instanceof WP_Site
			&& get_current_network_id() === (int) $site->network_id
			&& '1' !== $site->archived
			&& '1' !== $site->spam
			&& '1' !== $site->deleted;
	}

	/**
	 * Runs one operation under the selected site's table, option, and URL prefix.
	 *
	 * @template T
	 * @param int          $siteId Selected WordPress site identifier.
	 * @param callable():T $operation Site-scoped operation.
	 * @return T Operation result.
	 */
	private function withinSite( int $siteId, callable $operation ): mixed {
		switch_to_blog( $siteId );
		try {
			return $operation();
		} finally {
			restore_current_blog();
		}
	}
}
