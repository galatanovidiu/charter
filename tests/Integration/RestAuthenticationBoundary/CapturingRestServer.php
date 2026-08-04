<?php
/**
 * Header-safe REST server for integration tests.
 *
 * @package GalatanOvidiu\Charter
 */

declare(strict_types=1);

namespace GalatanOvidiu\Charter\Tests\Integration\RestAuthenticationBoundary;

use WP_REST_Server;

/**
 * Captures Core headers without writing to the PHPUnit process output stream.
 *
 * @since 0.1.0
 */
final class CapturingRestServer extends WP_REST_Server {

	/**
	 * Sanitized emitted response headers.
	 *
	 * @var array<string, string>
	 */
	private array $capturedHeaders = array();

	/**
	 * Captures one header instead of sending it through PHP.
	 *
	 * @param string $key   Header name.
	 * @param string $value Header value.
	 */
	public function send_header( $key, $value ): void {
		$this->capturedHeaders[ $key ] = $value;
	}

	/**
	 * Returns captured headers for exact Core behavior assertions.
	 *
	 * @return array<string, string>
	 */
	public function capturedHeaders(): array {
		return $this->capturedHeaders;
	}
}
