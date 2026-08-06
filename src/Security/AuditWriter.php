<?php
/**
 * Secret-free audit write and reconciliation contract.
 *
 * @package GalatanOvidiu\Charter
 */

declare(strict_types=1);

namespace GalatanOvidiu\Charter\Security;

/**
 * Persists and reconciles exact security events across non-atomic stores.
 *
 * @since 0.1.0
 */
interface AuditWriter {

	/**
	 * Records one validated security event.
	 *
	 * @param string      $issuer Exact issuer.
	 * @param string      $eventType Stable event type.
	 * @param string      $outcome Stable outcome.
	 * @param string      $reason Stable reason.
	 * @param int|null    $actorUserId Acting WordPress user.
	 * @param int|null    $representedUserId Represented user.
	 * @param string|null $clientId Exact client identifier.
	 * @param string|null $sourceAddress Normalized source when relevant.
	 * @param int|null    $timestamp Event timestamp.
	 * @param string|null $resourceIdentifier Exact protected resource when applicable.
	 * @param string|null $scopes Canonical scope set when applicable.
	 */
	public function record( string $issuer, string $eventType, string $outcome, string $reason, ?int $actorUserId = null, ?int $representedUserId = null, ?string $clientId = null, ?string $sourceAddress = null, ?int $timestamp = null, ?string $resourceIdentifier = null, ?string $scopes = null ): void;

	/**
	 * Reports whether one exact stable event is already durable.
	 *
	 * @param string   $issuer Exact issuer.
	 * @param int      $timestamp Exact event timestamp.
	 * @param string   $eventType Stable event type.
	 * @param string   $outcome Stable outcome.
	 * @param string   $reason Stable reason.
	 * @param int|null $actorUserId Acting WordPress user.
	 */
	public function hasEvent( string $issuer, int $timestamp, string $eventType, string $outcome, string $reason, ?int $actorUserId ): bool;
}
