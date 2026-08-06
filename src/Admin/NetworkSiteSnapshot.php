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
 *
 * @phpstan-type ContainmentSnapshot array{mode:string,changed_at:?int,actor:string,actor_user_id:?int,audit_pending:bool}
 * @phpstan-type SigningKeySnapshot array{source:string,status:string,database_fallback:bool,generation:int,adoption_count:int,changed_at:?int,actor:string,actor_user_id:?int,audit_pending:bool,mismatch_id:?string,transition_id:?string}
 */
final class NetworkSiteSnapshot {

	/**
	 * Creates one selected-site projection.
	 *
	 * @param int                  $siteId WordPress site identifier.
	 * @param string               $state Site OAuth lifecycle state.
	 * @param SiteIdentity|null    $identity Exact prepared identity.
	 * @param bool                 $storageReady Whether site tables are installed.
	 * @param int                  $activeGrantCount Complete active-grant count.
	 * @param array<GrantRecord>   $activeGrants Bounded active-grant page.
	 * @param array<AuditEvent>    $events Bounded site event history.
	 * @param array<string, mixed> $containment Secret-free containment status.
	 * @param array<string, mixed> $signingKey Secret-free signing-key status.
	 * @phpstan-param ContainmentSnapshot $containment
	 * @phpstan-param SigningKeySnapshot $signingKey
	 */
	public function __construct(
		private readonly int $siteId,
		private readonly string $state,
		private readonly ?SiteIdentity $identity,
		private readonly bool $storageReady,
		private readonly int $activeGrantCount,
		private readonly array $activeGrants,
		private readonly array $events,
		private readonly array $containment,
		private readonly array $signingKey
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

	/** Returns the issuer's current reversible containment mode. */
	public function containmentMode(): string {
		return $this->containment['mode'];
	}

	/** Returns the last containment transition time, when one exists. */
	public function containmentChangedAt(): ?int {
		return $this->containment['changed_at'];
	}

	/** Returns the stable last transition actor channel. */
	public function containmentActor(): string {
		return $this->containment['actor'];
	}

	/** Reports whether the applied mode still needs audit reconciliation. */
	public function containmentAuditPending(): bool {
		return $this->containment['audit_pending'];
	}

	/** Returns the configured root-key source. */
	public function signingKeySource(): string {
		return $this->signingKey['source'];
	}

	/** Returns the current secret-free key status. */
	public function signingKeyStatus(): string {
		return $this->signingKey['status'];
	}

	/** Reports database-backed fallback for WordPress-derived material. */
	public function signingKeyUsesDatabaseFallback(): bool {
		return $this->signingKey['database_fallback'];
	}

	/** Returns the current explicit credential generation. */
	public function signingKeyGeneration(): int {
		return $this->signingKey['generation'];
	}

	/** Returns the number of explicit replacement adoptions. */
	public function signingKeyAdoptionCount(): int {
		return $this->signingKey['adoption_count'];
	}

	/** Reports whether key-adoption audit reconciliation is pending. */
	public function signingKeyAuditPending(): bool {
		return $this->signingKey['audit_pending'];
	}

	/** Returns the exact non-secret current mismatch binding. */
	public function signingKeyMismatchId(): ?string {
		return $this->signingKey['mismatch_id'];
	}

	/** Returns the exact non-secret pending transition binding. */
	public function signingKeyTransitionId(): ?string {
		return $this->signingKey['transition_id'];
	}
}
