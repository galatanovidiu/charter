<?php
/**
 * Validated Client ID Metadata Document projection.
 *
 * @package GalatanOvidiu\Charter
 */

declare(strict_types=1);

namespace GalatanOvidiu\Charter\OAuth;

/** Carries only the authoritative public-client fields Charter consumes. */
final class RemoteClientMetadata {

	/**
	 * Creates one validated remote metadata projection.
	 *
	 * @param string $clientId Exact Client Identifier URL.
	 * @param string $name User-facing name.
	 * @param array  $redirectUris Exact validated redirects.
	 * @param array  $grantTypes Supported grant types.
	 * @param string $fingerprint Canonical consent binding.
	 * @phpstan-param list<string> $redirectUris
	 * @phpstan-param list<string> $grantTypes
	 */
	public function __construct(
		private readonly string $clientId,
		private readonly string $name,
		private readonly array $redirectUris,
		private readonly array $grantTypes,
		private readonly string $fingerprint
	) {
	}

	/** Returns the exact client identifier. */
	public function clientId(): string {
		return $this->clientId;
	}

	/** Returns the user-facing client name. */
	public function name(): string {
		return $this->name;
	}

	/**
	 * Returns exact validated redirect URIs.
	 *
	 * @return list<string>
	 */
	public function redirectUris(): array {
		return $this->redirectUris;
	}

	/**
	 * Returns the supported grant types.
	 *
	 * @return list<string>
	 */
	public function grantTypes(): array {
		return $this->grantTypes;
	}

	/** Returns the canonical consent binding. */
	public function fingerprint(): string {
		return $this->fingerprint;
	}

	/**
	 * Projects the current authorization-time client without persistence coupling.
	 *
	 * @param string $issuer Exact issuer.
	 */
	public function client( string $issuer ): Client {
		return new Client(
			$issuer,
			$this->clientId,
			$this->name,
			$this->redirectUris,
			Client::AUTH_NONE,
			$this->grantTypes,
			null,
			ClientRegistry::SOURCE_CIMD,
			$this->fingerprint
		);
	}
}
