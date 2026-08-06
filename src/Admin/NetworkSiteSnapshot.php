<?php
/**
 * Selected Multisite issuer projection.
 *
 * @package GalatanOvidiu\Charter
 */

declare(strict_types=1);

namespace GalatanOvidiu\Charter\Admin;

use GalatanOvidiu\Charter\OAuth\GrantRecord;
use GalatanOvidiu\Charter\Security\AuditEvent;
use GalatanOvidiu\Charter\Site\SiteIdentity;

/**
 * Carries bounded, non-secret state from one selected site boundary.
 *
 * @since 0.1.0
 */
final class NetworkSiteSnapshot {

	/**
	 * Creates one selected-site projection.
	 *
	 * @param int                $siteId WordPress site identifier.
	 * @param string             $state Site OAuth lifecycle state.
	 * @param SiteIdentity|null  $identity Exact prepared identity.
	 * @param bool               $storageReady Whether site tables are installed.
	 * @param int                $activeGrantCount Complete active-grant count.
	 * @param array<GrantRecord> $activeGrants Bounded active-grant page.
	 * @param array<AuditEvent>  $events Bounded site event history.
	 */
	public function __construct(
		private readonly int $siteId,
		private readonly string $state,
		private readonly ?SiteIdentity $identity,
		private readonly bool $storageReady,
		private readonly int $activeGrantCount,
		private readonly array $activeGrants,
		private readonly array $events
	) {
	}

	/** Returns the selected WordPress site identifier. */
	public function siteId(): int {
		return $this->siteId;
	}

	/** Returns the selected site's OAuth lifecycle state. */
	public function state(): string {
		return $this->state;
	}

	/** Returns the selected site's exact prepared identity. */
	public function identity(): ?SiteIdentity {
		return $this->identity;
	}

	/** Reports whether the selected site's OAuth tables are installed. */
	public function storageReady(): bool {
		return $this->storageReady;
	}

	/** Returns the selected site's complete active-grant count. */
	public function activeGrantCount(): int {
		return $this->activeGrantCount;
	}

	/**
	 * Returns the bounded active-grant page.
	 *
	 * @return array<GrantRecord>
	 */
	public function activeGrants(): array {
		return $this->activeGrants;
	}

	/**
	 * Returns the bounded recent event history.
	 *
	 * @return array<AuditEvent>
	 */
	public function events(): array {
		return $this->events;
	}
}
