<?php
/**
 * Bounded CIMD fetch result.
 *
 * @package GalatanOvidiu\Charter
 */

declare(strict_types=1);

namespace GalatanOvidiu\Charter\Tests\Prototype\CimdOutboundSafety;

use LogicException;

/**
 * Deliberately narrow result that is not a general evidence serialization surface.
 *
 * @since 0.1.0
 */
final class BoundFetchResult {

	/**
	 * Creates an already-bounded result.
	 *
	 * @param string                      $classification              Stable result classification.
	 * @param int|null                    $statusCode                  HTTP status, when available.
	 * @param string                      $body                        Bounded accepted body.
	 * @param array<string, list<string>> $headers Bounded response headers.
	 * @param int                         $bodyBytes                  Observed accepted body bytes.
	 * @param int                         $headerBytes                Observed header bytes.
	 * @param int                         $headerFields               Observed header field count.
	 * @param int                         $elapsedMilliseconds        Bounded elapsed time.
	 * @param int                         $requestCount               HTTP request count.
	 * @param bool                        $redirectFollowed           Whether cURL followed a redirect.
	 * @param bool                        $peerMatched                Whether the peer matched screening.
	 * @param bool                        $tlsHostnameVerified        Whether original-host TLS passed.
	 * @param string                      $mediaClassification        Media-type classification.
	 * @param string                      $contentCodingClassification Content-coding classification.
	 */
	public function __construct(
		private string $classification,
		private ?int $statusCode,
		private string $body,
		private array $headers,
		private int $bodyBytes,
		private int $headerBytes,
		private int $headerFields,
		private int $elapsedMilliseconds,
		private int $requestCount,
		private bool $redirectFollowed,
		private bool $peerMatched,
		private bool $tlsHostnameVerified,
		private string $mediaClassification,
		private string $contentCodingClassification
	) {}

	/**
	 * Projects the runtime's fixed observation without exposing a generic record API.
	 *
	 * @param array<string, mixed> $observation Fixed bounded observation.
	 */
	public static function fromObservation( array $observation ): self {
		$headers = array();
		if ( is_array( $observation['headers'] ?? null ) ) {
			foreach ( $observation['headers'] as $name => $values ) {
				if ( ! is_string( $name ) || ! is_array( $values ) ) {
					continue;
				}

				$bounded          = array_values( array_filter( $values, 'is_string' ) );
				$headers[ $name ] = $bounded;
			}
		}

		$statusCode = $observation['status_code'] ?? null;

		return new self(
			is_string( $observation['classification'] ?? null ) ? $observation['classification'] : 'invalid-observation',
			is_int( $statusCode ) ? $statusCode : null,
			is_string( $observation['body'] ?? null ) ? $observation['body'] : '',
			$headers,
			is_int( $observation['body_bytes'] ?? null ) ? max( 0, $observation['body_bytes'] ) : 0,
			is_int( $observation['header_bytes'] ?? null ) ? max( 0, $observation['header_bytes'] ) : 0,
			is_int( $observation['header_fields'] ?? null ) ? max( 0, $observation['header_fields'] ) : 0,
			is_int( $observation['elapsed_ms'] ?? null ) ? max( 0, $observation['elapsed_ms'] ) : 0,
			is_int( $observation['request_count'] ?? null ) ? max( 0, $observation['request_count'] ) : 0,
			true === ( $observation['redirect_followed'] ?? false ),
			true === ( $observation['peer_matched'] ?? false ),
			true === ( $observation['tls_hostname_verified'] ?? false ),
			is_string( $observation['media_classification'] ?? null ) ? $observation['media_classification'] : 'unavailable',
			is_string( $observation['content_coding'] ?? null ) ? $observation['content_coding'] : 'unavailable'
		);
	}

	/**
	 * Returns the stable result classification.
	 */
	public function classification(): string {
		return $this->classification;
	}

	/**
	 * Returns the HTTP status when a response was available.
	 */
	public function statusCode(): ?int {
		return $this->statusCode;
	}

	/**
	 * Returns only an accepted bounded body.
	 */
	public function body(): string {
		return $this->body;
	}

	/**
	 * Returns only accepted bounded headers.
	 *
	 * @return array<string, list<string>> Bounded headers.
	 */
	public function headers(): array {
		return $this->headers;
	}

	/**
	 * Returns observed accepted body bytes.
	 */
	public function bodyBytes(): int {
		return $this->bodyBytes;
	}

	/**
	 * Returns observed header bytes.
	 */
	public function headerBytes(): int {
		return $this->headerBytes;
	}

	/**
	 * Returns observed header fields.
	 */
	public function headerFields(): int {
		return $this->headerFields;
	}

	/**
	 * Returns bounded elapsed milliseconds.
	 */
	public function elapsedMilliseconds(): int {
		return $this->elapsedMilliseconds;
	}

	/**
	 * Returns the pre-request-approved send count.
	 */
	public function requestCount(): int {
		return $this->requestCount;
	}

	/**
	 * Reports whether cURL followed a redirect.
	 */
	public function redirectFollowed(): bool {
		return $this->redirectFollowed;
	}

	/**
	 * Reports whether the connected peer matched screening.
	 */
	public function peerMatched(): bool {
		return $this->peerMatched;
	}

	/**
	 * Reports whether original-host TLS verification passed.
	 */
	public function tlsHostnameVerified(): bool {
		return $this->tlsHostnameVerified;
	}

	/**
	 * Returns the media-type classification.
	 */
	public function mediaClassification(): string {
		return $this->mediaClassification;
	}

	/**
	 * Returns the content-coding classification.
	 */
	public function contentCodingClassification(): string {
		return $this->contentCodingClassification;
	}

	// The method always throws by design, so a return statement is unreachable.
	// phpcs:disable Squiz.Commenting.FunctionComment.InvalidNoReturn
	/**
	 * Rejects generic serialization of the bounded result.
	 *
	 * @return array<never, never>
	 * @throws LogicException Always; fetch results must not become evidence blobs.
	 */
	public function __serialize(): array {
		throw new LogicException( 'Bounded fetch results cannot be serialized.' );
	}
	// phpcs:enable Squiz.Commenting.FunctionComment.InvalidNoReturn
}
