<?php
/**
 * Disposable Slice 0 invocation evidence ledger.
 *
 * @package GalatanOvidiu\Charter
 */

declare(strict_types=1);

namespace GalatanOvidiu\Charter\Tests\Prototype\RestAuthenticationBoundary;

use WP_REST_Request;

/** Records only fixed labels, numeric identity, and context booleans. @since 0.1.0 */
final class InvocationLedger {
	/**
	 * Sanitized invocation records.
	 *
	 * @var list<array{request_id: int, route: string, route_label: string, phase: string, user_id: int, context_present: bool, outcome: string|null, depth: int}>
	 */
	private array $records = array();

	/**
	 * Records one sanitized invocation.
	 *
	 * @param WP_REST_Request $request Request under test.
	 * @param string          $routeLabel Fixed handler label.
	 * @param string          $phase Fixed invocation phase.
	 * @param bool            $contextPresent Whether proof context is present.
	 * @param int             $depth Current stack depth.
	 * @param string|null     $outcome Optional protocol outcome.
	 */
	public function record( WP_REST_Request $request, string $routeLabel, string $phase, bool $contextPresent, int $depth, ?string $outcome = null ): void {
		$this->records[] = array(
			'request_id'      => spl_object_id( $request ),
			'route'           => $request->get_route(),
			'route_label'     => $routeLabel,
			'phase'           => $phase,
			'user_id'         => get_current_user_id(),
			'context_present' => $contextPresent,
			'outcome'         => $outcome,
			'depth'           => $depth,
		);
	}

	/**
	 * Returns sanitized invocation evidence.
	 *
	 * @return list<array{request_id: int, route: string, route_label: string, phase: string, user_id: int, context_present: bool, outcome: string|null, depth: int}> Records.
	 */
	public function records(): array {
		return $this->records; }

	/** Clears invocation evidence. */
	public function reset(): void {
		$this->records = array(); }
}
