<?php
/**
 * Disposable Slice 0 sanitized Bearer validation result.
 *
 * @package GalatanOvidiu\Charter
 */

declare(strict_types=1);

namespace GalatanOvidiu\Charter\Tests\Prototype\RestAuthenticationBoundary;

/** Retains identity, resource, and scope labels without credential material. @since 0.1.0 */
final class BearerValidationResult {
	/**
	 * Exact protected-resource identifier.
	 *
	 * @var string
	 */
	private readonly string $resourceIdentifier;
	/**
	 * Validated scope labels.
	 *
	 * @var list<string>
	 */
	private readonly array $scopes;

	/**
	 * Creates one successful sanitized result.
	 *
	 * @param int           $userId Represented WordPress user ID.
	 * @param string        $resourceIdentifier Exact protected resource.
	 * @param array<string> $scopes Validated OAuth scopes.
	 */
	public function __construct( private readonly int $userId, string $resourceIdentifier, array $scopes ) {
		$this->resourceIdentifier = $resourceIdentifier;
		$this->scopes             = array_values( $scopes );
	}

	/** Returns the represented WordPress user ID. */
	public function userId(): int {
		return $this->userId; }
	/** Returns the exact protected-resource identifier. */
	public function resource(): string {
		return $this->resourceIdentifier; }
	/**
	 * Returns validated OAuth scopes.
	 *
	 * @return list<string> Validated scope labels.
	 */
	public function scopes(): array {
		return $this->scopes; }
}
