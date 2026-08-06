<?php
/**
 * Validated access-token context.
 *
 * @package GalatanOvidiu\Charter
 */

declare(strict_types=1);

namespace GalatanOvidiu\Charter\OAuth;

/**
 * Carries the exact identity established for one protected request.
 *
 * @since 0.1.0
 */
final class AccessTokenContext {

	/**
	 * Creates the validated request context.
	 *
	 * @since 0.1.0
	 *
	 * @param string        $issuer   Exact issuer.
	 * @param string        $resourceIdentifier Exact protected resource.
	 * @param string        $clientId Exact client identifier.
	 * @param int           $userId   Represented WordPress user.
	 * @param array<string> $scopes   Granted scopes.
	 */
	public function __construct(
		private readonly string $issuer,
		private readonly string $resourceIdentifier,
		private readonly string $clientId,
		private readonly int $userId,
		private readonly array $scopes
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
	 * Returns the exact client identifier.
	 *
	 * @since 0.1.0
	 */
	public function clientId(): string {
		return $this->clientId;
	}

	/**
	 * Returns the represented WordPress user identifier.
	 *
	 * @since 0.1.0
	 */
	public function userId(): int {
		return $this->userId;
	}

	/**
	 * Returns granted scope tokens.
	 *
	 * @since 0.1.0
	 *
	 * @return array<string> Granted scopes.
	 */
	public function scopes(): array {
		return $this->scopes;
	}
}
