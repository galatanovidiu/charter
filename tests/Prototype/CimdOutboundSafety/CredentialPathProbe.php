<?php
/**
 * Disposable Slice 0 credential-path isolation probe.
 *
 * @package GalatanOvidiu\Charter
 */

declare(strict_types=1);

namespace GalatanOvidiu\Charter\Tests\Prototype\CimdOutboundSafety;

use Closure;

/**
 * Models established credential paths without a CIMD dependency.
 *
 * @since 0.1.0
 */
final class CredentialPathProbe {

	/**
	 * Current local credential state.
	 *
	 * @var array{grant_active:bool, access_active:bool, refresh_family_active:bool, refresh_generation:int}
	 */
	private array $state;

	/**
	 * Exact client identity retained only by the local authorization record.
	 *
	 * @var string
	 */
	private readonly string $clientId;

	/**
	 * Retained P2 protected-request dispatcher.
	 *
	 * @var Closure(): bool|null
	 */
	private readonly ?Closure $protectedDispatcher;

	/**
	 * Creates an established proof-owned authorization.
	 *
	 * @param string        $clientId           Exact Client Identifier.
	 * @param callable|null $protectedDispatcher Retained P2 request dispatcher.
	 */
	private function __construct( string $clientId, ?callable $protectedDispatcher ) {
		$this->clientId            = $clientId;
		$this->protectedDispatcher = null !== $protectedDispatcher
			? Closure::fromCallable( $protectedDispatcher )
			: null;
		$this->state               = array(
			'grant_active'          => true,
			'access_active'         => true,
			'refresh_family_active' => true,
			'refresh_generation'    => 1,
		);
	}

	/**
	 * Creates the established local credential model.
	 *
	 * @param string        $clientId           Exact Client Identifier.
	 * @param callable|null $protectedDispatcher Optional retained P2 dispatcher.
	 */
	public static function forEstablishedAuthorization( string $clientId, ?callable $protectedDispatcher = null ): self {
		return new self( $clientId, $protectedDispatcher );
	}

	/**
	 * Returns current local state.
	 *
	 * @return array{grant_active:bool, access_active:bool, refresh_family_active:bool, refresh_generation:int} State.
	 */
	public function state(): array {
		return $this->state;
	}

	/**
	 * Completes local authorization-code exchange.
	 *
	 * @return array<string, mixed> Fixed observation.
	 */
	public function exchangeCode(): array {
		return $this->completed( 'code_exchanged' );
	}

	/**
	 * Rotates the local refresh generation.
	 *
	 * @return array<string, mixed> Fixed observation.
	 */
	public function refresh(): array {
		++$this->state['refresh_generation'];
		return $this->completed( 'refresh_rotated' );
	}

	/**
	 * Validates the access credential locally.
	 *
	 * @return array<string, mixed> Fixed observation.
	 */
	public function validateAccess(): array {
		return $this->completed( 'access_validated' );
	}

	/**
	 * Dispatches one protected request through the retained P2 boundary.
	 *
	 * @return array<string, mixed> Fixed observation.
	 */
	public function dispatchProtectedRequest(): array {
		$completed = null !== $this->protectedDispatcher && ( $this->protectedDispatcher )();
		return $this->completed( $completed ? 'protected_request_completed' : 'protected_request_unavailable' );
	}

	/**
	 * Returns a fixed zero-CIMD credential-path observation.
	 *
	 * @param string $classification Operation-specific result classification.
	 * @return array{classification:string, cimd_counters:array{dns:int,tcp:int,tls:int,http:int}, credential_disturbed:bool} Observation.
	 */
	private function completed( string $classification ): array {
		return array(
			'classification'       => '' !== $this->clientId ? $classification : 'invalid_local_identity',
			'cimd_counters'        => array(
				'dns'  => 0,
				'tcp'  => 0,
				'tls'  => 0,
				'http' => 0,
			),
			'credential_disturbed' => false,
		);
	}
}
