<?php
/**
 * Secret-free OAuth audit event.
 *
 * @package GalatanOvidiu\Charter
 */

declare(strict_types=1);

namespace GalatanOvidiu\Charter\Security;

/**
 * Carries one administrator-visible lifecycle event.
 *
 * @since 0.1.0
 */
final class AuditEvent {

	/**
	 * Creates one non-secret event projection.
	 *
	 * @param int         $occurredAt Event timestamp.
	 * @param string      $eventType Stable event type.
	 * @param int|null    $actorUserId Acting user.
	 * @param int|null    $representedUserId Represented user.
	 * @param string|null $clientId Exact client identifier.
	 * @param string      $outcome Stable outcome.
	 * @param string      $reason Stable reason.
	 * @param string|null $sourceAddress Normalized source.
	 */
	public function __construct(
		private readonly int $occurredAt,
		private readonly string $eventType,
		private readonly ?int $actorUserId,
		private readonly ?int $representedUserId,
		private readonly ?string $clientId,
		private readonly string $outcome,
		private readonly string $reason,
		private readonly ?string $sourceAddress
	) {
	}

	/** Returns the event timestamp. */
	public function occurredAt(): int {
		return $this->occurredAt;
	}

	/** Returns the stable event type. */
	public function eventType(): string {
		return $this->eventType;
	}

	/** Returns the acting user when present. */
	public function actorUserId(): ?int {
		return $this->actorUserId;
	}

	/** Returns the represented user when present. */
	public function representedUserId(): ?int {
		return $this->representedUserId;
	}

	/** Returns the exact client identifier when present. */
	public function clientId(): ?string {
		return $this->clientId;
	}

	/** Returns the stable outcome. */
	public function outcome(): string {
		return $this->outcome;
	}

	/** Returns the stable reason. */
	public function reason(): string {
		return $this->reason;
	}

	/** Returns the normalized source when security-relevant. */
	public function sourceAddress(): ?string {
		return $this->sourceAddress;
	}
}
