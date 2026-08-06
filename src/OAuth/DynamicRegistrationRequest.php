<?php
/**
 * Validated Dynamic Client Registration request.
 *
 * @package GalatanOvidiu\Charter
 */

declare(strict_types=1);

namespace GalatanOvidiu\Charter\OAuth;

/**
 * Carries only the immutable registration metadata Charter supports.
 *
 * @since 0.1.0
 */
final class DynamicRegistrationRequest {

	/**
	 * Creates one validated request.
	 *
	 * @param string        $name User-facing client name.
	 * @param array<string> $redirectUris Exact redirects.
	 * @param string        $authenticationMethod Required token method.
	 * @param bool          $supportsRefresh Whether refresh is declared.
	 */
	public function __construct(
		private readonly string $name,
		private readonly array $redirectUris,
		private readonly string $authenticationMethod,
		private readonly bool $supportsRefresh
	) {
	}

	/**
	 * Returns the client display name.
	 */
	public function name(): string {
		return $this->name;
	}

	/**
	 * Returns the exact registered redirects.
	 *
	 * @return array<string>
	 */
	public function redirectUris(): array {
		return $this->redirectUris;
	}

	/**
	 * Returns the token-endpoint authentication method.
	 */
	public function authenticationMethod(): string {
		return $this->authenticationMethod;
	}

	/**
	 * Reports whether refresh was declared.
	 */
	public function supportsRefresh(): bool {
		return $this->supportsRefresh;
	}
}
