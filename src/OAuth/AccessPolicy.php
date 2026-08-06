<?php
/**
 * Issuer-scoped protected-resource and scope policy.
 *
 * @package GalatanOvidiu\Charter
 */

declare(strict_types=1);

namespace GalatanOvidiu\Charter\OAuth;

/**
 * Builds one request-local view of available OAuth audience boundaries.
 *
 * Integrations register exact path resources before registering their own
 * namespaced scopes. Invalid and colliding registrations leave the prior
 * registry unchanged and return false.
 *
 * @since 0.1.0
 */
final class AccessPolicy {

	public const GENERAL_SCOPE = 'wordpress:access';

	/**
	 * Registered exact resources.
	 *
	 * @var array<string, ProtectedResourceDefinition>
	 */
	private array $resources = array();

	/**
	 * Registered globally unique scopes.
	 *
	 * @var array<string, ScopeDefinition>
	 */
	private array $scopes = array();

	/**
	 * Creates the built-in default resource and general scope.
	 *
	 * @param string $issuer Exact issuer and default resource.
	 */
	public function __construct(
		private readonly string $issuer
	) {
		$resource = new ProtectedResourceDefinition( 'charter', $issuer );
		$resource->addScope( self::GENERAL_SCOPE );
		$this->resources[ $issuer ]          = $resource;
		$this->scopes[ self::GENERAL_SCOPE ] = new ScopeDefinition(
			'charter',
			self::GENERAL_SCOPE,
			'WordPress access',
			'Access protected WordPress REST operations as your account. Normal WordPress permissions still apply.',
			array( $issuer )
		);
	}

	/** Returns the exact issuer and default-resource identifier. */
	public function issuer(): string {
		return $this->issuer;
	}

	/**
	 * Registers one narrower exact resource owned by an integration.
	 *
	 * @param string $owner                Plugin namespace owner.
	 * @param string $resourceIdentifier   Exact path-bearing resource.
	 * @param bool   $supportsGeneralScope Whether the general scope is accepted.
	 */
	public function registerResource( string $owner, string $resourceIdentifier, bool $supportsGeneralScope = false ): bool {
		if (
			! self::validOwner( $owner )
			|| 'charter' === $owner
			|| ! $this->isNarrowResource( $resourceIdentifier )
			|| isset( $this->resources[ $resourceIdentifier ] )
		) {
			return false;
		}

		$resource = new ProtectedResourceDefinition( $owner, $resourceIdentifier );
		if ( $supportsGeneralScope ) {
			$resource->addScope( self::GENERAL_SCOPE );
			$generalScope                        = $this->scopes[ self::GENERAL_SCOPE ];
			$this->scopes[ self::GENERAL_SCOPE ] = new ScopeDefinition(
				$generalScope->owner(),
				$generalScope->identifier(),
				$generalScope->name(),
				$generalScope->description(),
				array_merge( $generalScope->resources(), array( $resourceIdentifier ) )
			);
		}
		$this->resources[ $resourceIdentifier ] = $resource;

		return true;
	}

	/**
	 * Registers one collision-rejected, integration-namespaced scope.
	 *
	 * @param string        $owner               Plugin namespace owner.
	 * @param string        $scopeIdentifier     Exact scope token.
	 * @param string        $name                User-facing scope name.
	 * @param string        $description         User-facing consent description.
	 * @param array<string> $resourceIdentifiers Exact associated resources.
	 */
	public function registerScope( string $owner, string $scopeIdentifier, string $name, string $description, array $resourceIdentifiers ): bool {
		$name        = trim( $name );
		$description = trim( $description );
		$resources   = array_values( array_unique( $resourceIdentifiers ) );

		if (
			! self::validOwner( $owner )
			|| 'charter' === $owner
			|| ! self::validSpecializedScope( $owner, $scopeIdentifier )
			|| isset( $this->scopes[ $scopeIdentifier ] )
			|| array() === $resources
			|| ! self::validConsentText( $name, 128 )
			|| ! self::validConsentText( $description, 512 )
		) {
			return false;
		}

		foreach ( $resources as $resourceIdentifier ) {
			$resource = $this->resources[ $resourceIdentifier ] ?? null;
			if ( ! $resource instanceof ProtectedResourceDefinition || $resource->owner() !== $owner ) {
				return false;
			}
		}

		$this->scopes[ $scopeIdentifier ] = new ScopeDefinition( $owner, $scopeIdentifier, $name, $description, $resources );
		foreach ( $resources as $resourceIdentifier ) {
			$this->resources[ $resourceIdentifier ]->addScope( $scopeIdentifier );
		}

		return true;
	}

	/**
	 * Reports whether one exact resource is currently registered.
	 *
	 * @param string $resourceIdentifier Exact resource identifier.
	 */
	public function hasResource( string $resourceIdentifier ): bool {
		return isset( $this->resources[ $resourceIdentifier ] );
	}

	/**
	 * Returns every currently supported scope for authorization metadata.
	 *
	 * @return array<string> Scope identifiers.
	 */
	public function scopeIdentifiers(): array {
		$scopes = array_keys( $this->scopes );
		sort( $scopes, SORT_STRING );
		$scopes = array_values( array_diff( $scopes, array( self::GENERAL_SCOPE ) ) );
		array_unshift( $scopes, self::GENERAL_SCOPE );

		return $scopes;
	}

	/**
	 * Returns scopes currently supported by one exact resource.
	 *
	 * @param string $resourceIdentifier Exact resource identifier.
	 * @return array<string> Scope identifiers, or an empty array when absent.
	 */
	public function scopesForResource( string $resourceIdentifier ): array {
		$resource = $this->resources[ $resourceIdentifier ] ?? null;

		return $resource instanceof ProtectedResourceDefinition ? $resource->scopes() : array();
	}

	/**
	 * Canonicalizes a requested scope set for one exact resource.
	 *
	 * @param string        $resourceIdentifier Exact resource identifier.
	 * @param array<string> $scopeTokens        Delegated-access scope tokens.
	 * @return string|null Canonical scope string, or null when unsupported.
	 */
	public function canonicalScope( string $resourceIdentifier, array $scopeTokens ): ?string {
		$resource = $this->resources[ $resourceIdentifier ] ?? null;
		if ( ! $resource instanceof ProtectedResourceDefinition || array() === $scopeTokens ) {
			return null;
		}

		$scopes = array_values( array_unique( $scopeTokens ) );
		foreach ( $scopes as $scope ) {
			if ( ! $resource->supportsScope( $scope ) ) {
				return null;
			}
		}
		sort( $scopes, SORT_STRING );

		return implode( ' ', $scopes );
	}

	/**
	 * Reports whether a persisted exact resource/scope binding remains available.
	 *
	 * @param string $resourceIdentifier Exact resource identifier.
	 * @param string $canonicalScope     Canonical scope string.
	 */
	public function bindingAvailable( string $resourceIdentifier, string $canonicalScope ): bool {
		$scopeTokens = self::canonicalScopeTokens( $canonicalScope );

		return null !== $scopeTokens && $canonicalScope === $this->canonicalScope( $resourceIdentifier, $scopeTokens );
	}

	/**
	 * Reports whether a route's exact requirements are registered together.
	 *
	 * @param string        $resourceIdentifier Exact resource identifier.
	 * @param array<string> $requiredScopes     Exact required scopes.
	 */
	public function assignmentAvailable( string $resourceIdentifier, array $requiredScopes ): bool {
		if ( array() === $requiredScopes || count( $requiredScopes ) !== count( array_unique( $requiredScopes ) ) ) {
			return false;
		}

		$resource = $this->resources[ $resourceIdentifier ] ?? null;
		if ( ! $resource instanceof ProtectedResourceDefinition ) {
			return false;
		}
		foreach ( $requiredScopes as $scope ) {
			if ( ! $resource->supportsScope( $scope ) ) {
				return false;
			}
		}

		return true;
	}

	/**
	 * Returns consent definitions in canonical scope order.
	 *
	 * @param string $canonicalScope Canonical scope string.
	 * @return array<ScopeDefinition> Registered definitions.
	 */
	public function consentScopes( string $canonicalScope ): array {
		$scopeTokens = self::canonicalScopeTokens( $canonicalScope );
		if ( null === $scopeTokens ) {
			return array();
		}

		$definitions = array();
		foreach ( $scopeTokens as $scope ) {
			$definition = $this->scopes[ $scope ] ?? null;
			if ( ! $definition instanceof ScopeDefinition ) {
				return array();
			}
			$definitions[] = $definition;
		}

		return $definitions;
	}

	/**
	 * Reports whether a resource is an exact narrower path under this issuer.
	 *
	 * @param string $resourceIdentifier Candidate resource identifier.
	 */
	private function isNarrowResource( string $resourceIdentifier ): bool {
		if (
			! str_starts_with( $resourceIdentifier, $this->issuer . '/' )
			|| $resourceIdentifier === $this->issuer . '/'
			|| str_contains( $resourceIdentifier, '?' )
			|| str_contains( $resourceIdentifier, '#' )
			|| 2048 < strlen( $resourceIdentifier )
		) {
			return false;
		}

		$parts = parse_url( $resourceIdentifier ); // phpcs:ignore WordPress.WP.AlternativeFunctions.parse_url_parse_url -- Pure registration value parsing also runs outside WordPress in unit tests.
		if ( ! is_array( $parts ) || ! is_string( $parts['path'] ?? null ) ) {
			return false;
		}
		$path = $parts['path'];
		if (
			substr( $resourceIdentifier, strlen( $this->issuer ) ) !== $path
			|| str_contains( $path, '\\' )
			|| str_contains( $path, '%' )
			|| 1 === preg_match( '/[\x00-\x20\x7F]/', $path )
			|| array_key_exists( 'user', $parts )
			|| array_key_exists( 'pass', $parts )
			|| array_key_exists( 'query', $parts )
			|| array_key_exists( 'fragment', $parts )
		) {
			return false;
		}

		$segments = explode( '/', trim( $path, '/' ) );

		return ! in_array( '', $segments, true )
			&& ! in_array( '.', $segments, true )
			&& ! in_array( '..', $segments, true );
	}

	/**
	 * Reports whether one plugin namespace owner is valid.
	 *
	 * @param string $owner Candidate namespace owner.
	 */
	private static function validOwner( string $owner ): bool {
		return 1 === preg_match( '/^[a-z][a-z0-9-]{0,63}$/D', $owner );
	}

	/**
	 * Reports whether one specialized scope belongs to its declared owner.
	 *
	 * @param string $owner           Declared namespace owner.
	 * @param string $scopeIdentifier Candidate scope identifier.
	 */
	private static function validSpecializedScope( string $owner, string $scopeIdentifier ): bool {
		return 128 >= strlen( $scopeIdentifier )
			&& str_starts_with( $scopeIdentifier, $owner . ':' )
			&& $scopeIdentifier !== $owner . ':'
			&& 1 === preg_match( '/^[\x21\x23-\x5B\x5D-\x7E]+$/D', $scopeIdentifier );
	}

	/**
	 * Reports whether consent copy is bounded visible text.
	 *
	 * @param string $text      Candidate consent text.
	 * @param int    $maxLength Maximum byte length.
	 */
	private static function validConsentText( string $text, int $maxLength ): bool {
		return '' !== $text
			&& $maxLength >= strlen( $text )
			&& 0 === preg_match( '/[\x00-\x1F\x7F]/', $text );
	}

	/**
	 * Parses and verifies one already-canonical persisted scope string.
	 *
	 * @param string $canonicalScope Candidate canonical scope string.
	 * @return array<string>|null Scope tokens.
	 */
	private static function canonicalScopeTokens( string $canonicalScope ): ?array {
		if ( '' === $canonicalScope || trim( $canonicalScope ) !== $canonicalScope ) {
			return null;
		}
		$tokens = explode( ' ', $canonicalScope );
		if ( in_array( '', $tokens, true ) || count( $tokens ) !== count( array_unique( $tokens ) ) ) {
			return null;
		}
		$sorted = $tokens;
		sort( $sorted, SORT_STRING );

		return $tokens === $sorted ? $tokens : null;
	}
}
