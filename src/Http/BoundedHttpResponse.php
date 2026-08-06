<?php
/**
 * Accepted bounded remote JSON response.
 *
 * @package GalatanOvidiu\Charter
 */

declare(strict_types=1);

namespace GalatanOvidiu\Charter\Http;

/** Carries only the complete validated representation and cache inputs. */
final class BoundedHttpResponse {

	/**
	 * Creates one accepted complete response.
	 *
	 * @param string                     $body Complete response body.
	 * @param array<string,list<string>> $headers Duplicate-preserving response headers.
	 * @param int                        $requestTime Request wall time.
	 * @param int                        $responseTime Response wall time.
	 */
	public function __construct(
		private readonly string $body,
		private readonly array $headers,
		private readonly int $requestTime,
		private readonly int $responseTime
	) {
	}

	/** Returns the complete response body. */
	public function body(): string {
		return $this->body;
	}

	/**
	 * Returns duplicate-preserving response headers.
	 *
	 * @return array<string,list<string>>
	 */
	public function headers(): array {
		return $this->headers;
	}

	/** Returns the request wall time. */
	public function requestTime(): int {
		return $this->requestTime;
	}

	/** Returns the response wall time. */
	public function responseTime(): int {
		return $this->responseTime;
	}
}
