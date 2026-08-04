<?php
/**
 * Disposable Slice 0 request-keyed identity/context stack.
 *
 * @package GalatanOvidiu\Charter
 */

declare(strict_types=1);

namespace GalatanOvidiu\Charter\Tests\Prototype\RestAuthenticationBoundary;

use RuntimeException;
use WP_REST_Request;

/** Restores nested WordPress identity and proof context in LIFO order. @since 0.1.0 */
final class RequestContextStack {
	/**
	 * Nested request frames.
	 *
	 * @var list<array{request_id: int, prior_user_id: int, prior_context: BearerValidationResult|null}>
	 */
	private array $frames = array();
	/**
	 * Current sanitized OAuth context.
	 *
	 * @var BearerValidationResult|null
	 */
	private ?BearerValidationResult $current = null;

	/**
	 * Enters one request context.
	 *
	 * @param WP_REST_Request        $request Matched request.
	 * @param BearerValidationResult $context Validated context.
	 */
	public function enter( WP_REST_Request $request, BearerValidationResult $context ): void {
		$this->frames[] = array(
			'request_id'    => spl_object_id( $request ),
			'prior_user_id' => get_current_user_id(),
			'prior_context' => $this->current,
		);
		$this->current  = $context;
		wp_set_current_user( $context->userId() );
	}

	/**
	 * Leaves one request context.
	 *
	 * @param WP_REST_Request $request Matched request.
	 * @throws RuntimeException On invalid nesting.
	 */
	public function leave( WP_REST_Request $request ): void {
		$frame = end( $this->frames );
		if ( ! is_array( $frame ) || spl_object_id( $request ) !== $frame['request_id'] ) {
			throw new RuntimeException( 'rest_auth_boundary_context_order_invalid' ); }
		array_pop( $this->frames );
		$this->current = $frame['prior_context'];
		wp_set_current_user( $frame['prior_user_id'] );
	}

	/** Returns the current sanitized context. */
	public function current(): ?BearerValidationResult {
		return $this->current; }
	/** Returns total nested stack depth. */
	public function depth(): int {
		return count( $this->frames ); }
	/**
	 * Returns depth for one request.
	 *
	 * @param WP_REST_Request $request Request to inspect.
	 * @return int Matching frame count.
	 */
	public function depthFor( WP_REST_Request $request ): int {
		$requestId = spl_object_id( $request );
		return count( array_filter( $this->frames, static fn ( array $frame ): bool => $requestId === $frame['request_id'] ) );
	}
	/**
	 * Reports whether a request has an active frame.
	 *
	 * @param WP_REST_Request $request Request to inspect.
	 */
	public function hasFor( WP_REST_Request $request ): bool {
		return $this->depthFor( $request ) > 0; }
	/**
	 * Restores frames to an earlier depth.
	 *
	 * @param int $depth Target depth.
	 */
	public function restoreToDepth( int $depth ): void {
		$currentDepth = count( $this->frames );
		while ( $currentDepth > $depth ) {
			$frame = array_pop( $this->frames );
			if ( ! is_array( $frame ) ) {
				break; }
			$this->current = $frame['prior_context'];
			wp_set_current_user( $frame['prior_user_id'] );
			--$currentDepth;
		}
	}
	/** Restores every remaining frame. */
	public function restoreAll(): void {
		$this->restoreToDepth( 0 ); }
}
