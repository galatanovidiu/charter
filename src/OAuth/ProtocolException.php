<?php
/**
 * OAuth protocol error.
 *
 * @package GalatanOvidiu\Charter
 */

declare(strict_types=1);

namespace GalatanOvidiu\Charter\OAuth;

use RuntimeException;

/**
 * Carries a bounded public OAuth error without sensitive context.
 *
 * @since 0.1.0
 */
final class ProtocolException extends RuntimeException {

	/**
	 * Creates a protocol exception.
	 *
	 * @since 0.1.0
	 *
	 * @param string      $error       OAuth error code.
	 * @param string      $description Safe public description.
	 * @param int         $status      HTTP status.
	 * @param string|null $redirectUri Validated redirect URI, when redirecting is safe.
	 * @param string|null $state       Client state to preserve.
	 * @param int|null    $retryAfter Retry delay for a throttled request.
	 */
	public function __construct(
		private readonly string $error,
		string $description,
		private readonly int $status = 400,
		private readonly ?string $redirectUri = null,
		private readonly ?string $state = null,
		private readonly ?int $retryAfter = null
	) {
		parent::__construct( $description );
	}

	/**
	 * Returns the OAuth error code.
	 *
	 * @since 0.1.0
	 */
	public function error(): string {
		return $this->error;
	}

	/**
	 * Returns the response status.
	 *
	 * @since 0.1.0
	 */
	public function status(): int {
		return $this->status;
	}

	/**
	 * Returns a prevalidated redirect URI, when available.
	 *
	 * @since 0.1.0
	 */
	public function redirectUri(): ?string {
		return $this->redirectUri;
	}

	/**
	 * Returns client state to preserve, when available.
	 *
	 * @since 0.1.0
	 */
	public function state(): ?string {
		return $this->state;
	}

	/** Returns the bounded Retry-After delay when throttled. */
	public function retryAfter(): ?int {
		return $this->retryAfter;
	}
}
