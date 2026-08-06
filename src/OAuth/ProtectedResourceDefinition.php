<?php
/**
 * Registered OAuth protected resource.
 *
 * @package GalatanOvidiu\Charter
 */

declare(strict_types=1);

namespace GalatanOvidiu\Charter\OAuth;

/**
 * Carries one exact audience and its currently available scopes.
 *
 * @since 0.1.0
 */
final class ProtectedResourceDefinition {

	/**
	 * Exact supported scope set.
	 *
	 * @var array<string, true>
	 */
	private array $scopes = array();

	/**
	 * Creates one exact protected resource.
	 *
	 * @param string $owner      Integration namespace owner.
	 * @param string $identifier Exact resource identifier.
	 */
	public function __construct(
		private readonly string $owner,
		private readonly string $identifier
	) {
	}

	/** Returns the integration namespace owner. */
	public function owner(): string {
		return $this->owner;
	}

	/** Returns the exact protected-resource identifier. */
	public function identifier(): string {
		return $this->identifier;
	}

	/**
	 * Adds one validated associated scope.
	 *
	 * @param string $scope Exact scope identifier.
	 */
	public function addScope( string $scope ): void {
		$this->scopes[ $scope ] = true;
	}

	/**
	 * Reports whether the resource currently supports one scope.
	 *
	 * @param string $scope Exact scope identifier.
	 */
	public function supportsScope( string $scope ): bool {
		return isset( $this->scopes[ $scope ] );
	}

	/**
	 * Returns exact supported scopes with the general scope first.
	 *
	 * @return array<string> Scope identifiers.
	 */
	public function scopes(): array {
		$scopes = array_keys( $this->scopes );
		sort( $scopes, SORT_STRING );
		if ( in_array( AccessPolicy::GENERAL_SCOPE, $scopes, true ) ) {
			$scopes = array_values( array_diff( $scopes, array( AccessPolicy::GENERAL_SCOPE ) ) );
			array_unshift( $scopes, AccessPolicy::GENERAL_SCOPE );
		}

		return $scopes;
	}
}
