<?php
/**
 * Disposable Slice 0 in-memory Bearer record.
 *
 * @package GalatanOvidiu\Charter
 */

declare(strict_types=1);

namespace GalatanOvidiu\Charter\Tests\Prototype\RestAuthenticationBoundary;

/** Models validation state without retaining credential material itself. @since 0.1.0 */
final class SyntheticBearerRecord {
	/**
	 * Exact protected-resource identifier.
	 *
	 * @var string
	 */
	private readonly string $resourceIdentifier;
	/**
	 * Bound OAuth scopes.
	 *
	 * @var list<string>
	 */
	private readonly array $scopes;

	/**
	 * Creates one synthetic validation record.
	 *
	 * @param string        $issuer Exact bound issuer.
	 * @param string        $resourceIdentifier Exact bound resource.
	 * @param string        $clientId Bound client label.
	 * @param int           $userId Represented user ID.
	 * @param array<string> $scopes Bound OAuth scopes.
	 * @param bool          $tokenCurrent Whether token state and time are current.
	 * @param bool          $clientCurrent Whether client state is current.
	 * @param bool          $userCurrent Whether user state is current.
	 * @param bool          $grantCurrent Whether grant state is current.
	 * @param bool          $policyAllows Whether current policy permits access.
	 */
	public function __construct(
		private readonly string $issuer,
		string $resourceIdentifier,
		private readonly string $clientId,
		private readonly int $userId,
		array $scopes,
		private readonly bool $tokenCurrent = true,
		private readonly bool $clientCurrent = true,
		private readonly bool $userCurrent = true,
		private readonly bool $grantCurrent = true,
		private readonly bool $policyAllows = true
	) {
		$this->resourceIdentifier = $resourceIdentifier;
		$this->scopes             = array_values( $scopes );
	}

	/** Returns the exact bound issuer. */
	public function issuer(): string {
		return $this->issuer; }
	/** Returns the exact bound resource. */
	public function resource(): string {
		return $this->resourceIdentifier; }
	/** Returns the bound client label. */
	public function clientId(): string {
		return $this->clientId; }
	/** Returns the represented WordPress user ID. */
	public function userId(): int {
		return $this->userId; }
	/**
	 * Returns bound OAuth scopes.
	 *
	 * @return list<string> Bound scope labels.
	 */
	public function scopes(): array {
		return $this->scopes; }
	/** Reports whether every synthetic current-state check passes. */
	public function isCurrent(): bool {
		return $this->tokenCurrent && $this->clientCurrent && $this->userCurrent && $this->grantCurrent && $this->policyAllows; }
}
