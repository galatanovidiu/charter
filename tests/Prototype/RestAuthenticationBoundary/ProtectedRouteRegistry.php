<?php
/**
 * Disposable Slice 0 matched-handler assignment registry.
 *
 * @package GalatanOvidiu\Charter
 */

declare(strict_types=1);

namespace GalatanOvidiu\Charter\Tests\Prototype\RestAuthenticationBoundary;

/** Marks only the exact handler WordPress later returns from route matching. @since 0.1.0 */
final class ProtectedRouteRegistry {
	private const ATTRIBUTE = 'charter_slice0_protected_resource';

	/**
	 * Decorates one ordinary handler with an exact assignment.
	 *
	 * @param array<string, mixed> $handler Ordinary WordPress handler.
	 * @param string               $routeLabel Fixed non-secret handler label.
	 * @param string               $resourceIdentifier Exact resource identifier.
	 * @param array<string>        $requiredScopes Required OAuth scopes.
	 * @return array<string, mixed> Decorated WordPress handler.
	 */
	public static function assign( array $handler, string $routeLabel, string $resourceIdentifier, array $requiredScopes ): array {
		$handler[ self::ATTRIBUTE ] = new ProtectedRouteAssignment( $routeLabel, $resourceIdentifier, $requiredScopes );
		return $handler;
	}

	/**
	 * Reads only the marker on the Core-selected handler.
	 *
	 * @param array<array-key, mixed> $handler Core-selected handler.
	 * @return ProtectedRouteAssignment|null Exact assignment or null.
	 */
	public static function assignmentFor( array $handler ): ?ProtectedRouteAssignment {
		$assignment = $handler[ self::ATTRIBUTE ] ?? null;
		return $assignment instanceof ProtectedRouteAssignment ? $assignment : null;
	}

	/** This class contains static registry mechanics only. */
	private function __construct() {
	}
}
