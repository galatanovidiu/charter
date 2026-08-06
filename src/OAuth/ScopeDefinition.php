<?php
/**
 * Registered OAuth scope presentation.
 *
 * @package GalatanOvidiu\Charter
 */

declare(strict_types=1);

namespace GalatanOvidiu\Charter\OAuth;

/**
 * Carries one globally unambiguous scope and its consent copy.
 *
 * @since 0.1.0
 */
final class ScopeDefinition {

	/**
	 * Creates one validated scope definition.
	 *
	 * @param string        $owner       Integration namespace owner.
	 * @param string        $identifier  Exact OAuth scope token.
	 * @param string        $name        User-facing scope name.
	 * @param string        $description User-facing consent description.
	 * @param array<string> $resources   Exact associated resources.
	 */
	public function __construct(
		private readonly string $owner,
		private readonly string $identifier,
		private readonly string $name,
		private readonly string $description,
		private readonly array $resources
	) {
	}

	/** Returns the integration namespace owner. */
	public function owner(): string {
		return $this->owner;
	}

	/** Returns the exact scope token. */
	public function identifier(): string {
		return $this->identifier;
	}

	/** Returns the user-facing scope name. */
	public function name(): string {
		return $this->name;
	}

	/** Returns the user-facing consent description. */
	public function description(): string {
		return $this->description;
	}

	/**
	 * Returns exact associated resources.
	 *
	 * @return array<string> Resource identifiers.
	 */
	public function resources(): array {
		return $this->resources;
	}
}
