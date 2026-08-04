<?php
/**
 * Disposable Slice 0 protected-route assignment.
 *
 * @package GalatanOvidiu\Charter
 */

declare(strict_types=1);

namespace GalatanOvidiu\Charter\Tests\Prototype\RestAuthenticationBoundary;

use InvalidArgumentException;

/**
 * Carries one exact matched-handler resource and scope assignment.
 *
 * @since 0.1.0
 */
final class ProtectedRouteAssignment {
	/**
	 * Exact protected-resource identifier.
	 *
	 * @var string
	 */
	private readonly string $resourceIdentifier;
	/**
	 * Exact issuer origin.
	 *
	 * @var string
	 */
	private readonly string $issuerIdentifier;

	/**
	 * Required OAuth scopes.
	 *
	 * @var list<string>
	 */
	private readonly array $requiredScopes;

	/**
	 * Creates one exact handler assignment.
	 *
	 * @param string        $routeLabel Fixed non-secret handler label.
	 * @param string        $resourceIdentifier Exact protected-resource identifier.
	 * @param array<string> $requiredScopes Required OAuth scopes.
	 * @throws InvalidArgumentException When the assignment is invalid.
	 */
	public function __construct( private readonly string $routeLabel, string $resourceIdentifier, array $requiredScopes ) {
		$parts  = wp_parse_url( $resourceIdentifier );
		$scopes = array_values( array_unique( $requiredScopes ) );

		$hasForbiddenComponent = isset( $parts['user'] )
			|| isset( $parts['pass'] )
			|| isset( $parts['query'] )
			|| isset( $parts['fragment'] );

		if ( '' === $routeLabel || ! is_array( $parts ) || 'https' !== ( $parts['scheme'] ?? null ) || ! is_string( $parts['host'] ?? null ) || $hasForbiddenComponent || array() === $scopes ) {
			throw new InvalidArgumentException( 'rest_auth_boundary_assignment_invalid' );
		}

		foreach ( $scopes as $scope ) {
			if ( '' === $scope || 1 !== preg_match( '/^[\x21\x23-\x5B\x5D-\x7E]+$/D', $scope ) ) {
				throw new InvalidArgumentException( 'rest_auth_boundary_scope_invalid' );
			}
		}

		$this->resourceIdentifier = $resourceIdentifier;
		$this->issuerIdentifier   = 'https://' . $parts['host'] . ( is_int( $parts['port'] ?? null ) ? ':' . $parts['port'] : '' );
		$this->requiredScopes     = $scopes;
	}

	/** Returns the fixed handler label. */
	public function routeLabel(): string {
		return $this->routeLabel; }

	/** Returns the exact protected-resource identifier. */
	public function resource(): string {
		return $this->resourceIdentifier; }

	/** Returns the resource's exact issuer origin. */
	public function issuer(): string {
		return $this->issuerIdentifier;
	}

	/** Returns the exact RFC 9728 metadata URL. */
	public function resourceMetadataUri(): string {
		$parts = wp_parse_url( $this->resourceIdentifier );
		$path  = is_array( $parts ) && is_string( $parts['path'] ?? null ) ? rtrim( $parts['path'], '/' ) : '';

		return $this->issuer() . '/.well-known/oauth-protected-resource' . $path;
	}

	/**
	 * Returns complete required OAuth scopes.
	 *
	 * @return list<string> Complete required OAuth scopes.
	 */
	public function requiredScopes(): array {
		return $this->requiredScopes; }
}
