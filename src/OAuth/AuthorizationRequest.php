<?php
/**
 * Validated OAuth authorization request.
 *
 * @package GalatanOvidiu\Charter
 */

declare(strict_types=1);

namespace GalatanOvidiu\Charter\OAuth;

/**
 * Carries exact authorization bindings after validation.
 *
 * @since 0.1.0
 */
final class AuthorizationRequest {

	/**
	 * Creates the validated request.
	 *
	 * @since 0.1.0
	 *
	 * @param string      $issuer        Exact issuer.
	 * @param string      $resourceIdentifier Exact protected resource.
	 * @param Client      $client        Exact active client.
	 * @param string      $redirectUri   Exact bound redirect URI.
	 * @param string      $scope         Canonical scope string.
	 * @param string      $codeChallenge S256 PKCE challenge.
	 * @param string|null $state         Optional client state.
	 * @param bool        $continuingAccessRequested Whether refresh access was requested.
	 */
	public function __construct(
		private readonly string $issuer,
		private readonly string $resourceIdentifier,
		private readonly Client $client,
		private readonly string $redirectUri,
		private readonly string $scope,
		private readonly string $codeChallenge,
		private readonly ?string $state,
		private readonly bool $continuingAccessRequested = false
	) {
	}

	/**
	 * Returns the exact issuer.
	 *
	 * @since 0.1.0
	 */
	public function issuer(): string {
		return $this->issuer;
	}

	/**
	 * Returns the exact protected resource.
	 *
	 * @since 0.1.0
	 */
	public function resource(): string {
		return $this->resourceIdentifier;
	}

	/**
	 * Returns the exact active client.
	 *
	 * @since 0.1.0
	 */
	public function client(): Client {
		return $this->client;
	}

	/**
	 * Returns the exact bound redirect URI.
	 *
	 * @since 0.1.0
	 */
	public function redirectUri(): string {
		return $this->redirectUri;
	}

	/**
	 * Returns the canonical scope string.
	 *
	 * @since 0.1.0
	 */
	public function scope(): string {
		return $this->scope;
	}

	/**
	 * Returns the S256 PKCE challenge.
	 *
	 * @since 0.1.0
	 */
	public function codeChallenge(): string {
		return $this->codeChallenge;
	}

	/**
	 * Returns optional client state.
	 *
	 * @since 0.1.0
	 */
	public function state(): ?string {
		return $this->state;
	}

	/**
	 * Reports whether the user is being asked to approve continuing access.
	 *
	 * @since 0.1.0
	 */
	public function continuingAccessRequested(): bool {
		return $this->continuingAccessRequested;
	}
}
