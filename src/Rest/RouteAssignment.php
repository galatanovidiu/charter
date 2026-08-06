<?php
/**
 * Protected REST handler assignment.
 *
 * @package GalatanOvidiu\Charter
 */

declare(strict_types=1);

namespace GalatanOvidiu\Charter\Rest;

use InvalidArgumentException;

/**
 * Carries one exact handler's resource and scope requirements.
 *
 * @since 0.1.0
 */
final class RouteAssignment {

	public const DEFAULT_RESOURCE = 'default';

	/**
	 * Creates an exact REST handler assignment.
	 *
	 * @since 0.1.0
	 *
	 * @param string        $resourceIdentifier Default sentinel or exact resource identifier.
	 * @param array<string> $requiredScopes Required OAuth scopes.
	 * @throws InvalidArgumentException When the assignment is ambiguous.
	 */
	public function __construct(
		private readonly string $resourceIdentifier,
		private readonly array $requiredScopes
	) {
		if ( '' === $resourceIdentifier || array() === $requiredScopes ) {
			throw new InvalidArgumentException( 'charter_route_assignment_invalid' );
		}

		foreach ( $requiredScopes as $scope ) {
			if ( 1 !== preg_match( '/^[\x21\x23-\x5B\x5D-\x7E]+$/D', $scope ) ) {
				throw new InvalidArgumentException( 'charter_route_assignment_invalid' );
			}
		}
	}

	/**
	 * Resolves the exact resource for the current issuer.
	 *
	 * @since 0.1.0
	 *
	 * @param string $issuer Exact current issuer.
	 */
	public function resource( string $issuer ): string {
		return self::DEFAULT_RESOURCE === $this->resourceIdentifier ? $issuer : $this->resourceIdentifier;
	}

	/**
	 * Returns exact required scope tokens.
	 *
	 * @since 0.1.0
	 *
	 * @return array<string> Required scopes.
	 */
	public function requiredScopes(): array {
		return $this->requiredScopes;
	}
}
