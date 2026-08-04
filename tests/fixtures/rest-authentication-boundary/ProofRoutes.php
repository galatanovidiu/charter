<?php
/**
 * Disposable REST routes shared by the Slice 0 P2 workers.
 *
 * @package GalatanOvidiu\Charter
 */

declare(strict_types=1);

namespace GalatanOvidiu\Charter\Tests\Fixtures\RestAuthenticationBoundary;

use GalatanOvidiu\Charter\Tests\Prototype\RestAuthenticationBoundary\ProtectedRouteRegistry;
use GalatanOvidiu\Charter\Tests\Prototype\RestAuthenticationBoundary\RestAuthenticationBoundary;
use GalatanOvidiu\Charter\Tests\Prototype\RestAuthenticationBoundary\SyntheticBearerFixtures;
use WP_REST_Request;
use WP_REST_Response;
use WP_REST_Server;

/**
 * Registers only proof-owned public, protected, and denied routes.
 */
final class ProofRoutes {

	public const NAMESPACE = 'charter-p2-worker/v1';

	public const PUBLIC_ROUTE = '/' . self::NAMESPACE . '/public';

	public const PROTECTED_ROUTE = '/' . self::NAMESPACE . '/protected';

	public const DENIED_ROUTE = '/' . self::NAMESPACE . '/denied';

	public const MULTI_ROUTE = '/' . self::NAMESPACE . '/multi';

	public const BATCH_PUBLIC_ROUTE = '/' . self::NAMESPACE . '/batch-public';

	public const BATCH_PROTECTED_ROUTE = '/' . self::NAMESPACE . '/batch-protected';

	/**
	 * Permission callback count for the current worker.
	 *
	 * @var int
	 */
	private int $permissionCount = 0;

	/**
	 * Main callback count for the current worker.
	 *
	 * @var int
	 */
	private int $callbackCount = 0;

	/**
	 * Creates one proof route registry.
	 *
	 * @param RestAuthenticationBoundary $boundary Installed proof boundary.
	 */
	public function __construct( private readonly RestAuthenticationBoundary $boundary ) {}

	/**
	 * Registers the exact proof handlers on one disposable server.
	 *
	 * @param WP_REST_Server $server Disposable server.
	 */
	public function register( WP_REST_Server $server ): void {
		$server->register_route(
			self::NAMESPACE,
			self::PUBLIC_ROUTE,
			$this->handler( 'public', true )
		);

		$server->register_route(
			self::NAMESPACE,
			self::PROTECTED_ROUTE,
			ProtectedRouteRegistry::assign(
				$this->handler( 'protected', true ),
				'protected',
				SyntheticBearerFixtures::DEFAULT_RESOURCE,
				array( SyntheticBearerFixtures::GENERAL_SCOPE )
			)
		);

		$server->register_route(
			self::NAMESPACE,
			self::MULTI_ROUTE,
			array(
				ProtectedRouteRegistry::assign(
					$this->handler( 'multi-get', true, 'GET' ),
					'multi-get',
					SyntheticBearerFixtures::DEFAULT_RESOURCE,
					array( SyntheticBearerFixtures::GENERAL_SCOPE )
				),
				ProtectedRouteRegistry::assign(
					$this->handler( 'multi-post', true, 'POST' ),
					'multi-post',
					SyntheticBearerFixtures::ISOLATED_RESOURCE,
					array( SyntheticBearerFixtures::GENERAL_SCOPE )
				),
			)
		);

		$server->register_route(
			self::NAMESPACE,
			self::DENIED_ROUTE,
			ProtectedRouteRegistry::assign(
				$this->handler( 'denied', false ),
				'denied',
				SyntheticBearerFixtures::DEFAULT_RESOURCE,
				array( SyntheticBearerFixtures::GENERAL_SCOPE )
			)
		);
	}

	/**
	 * Registers POST-capable routes used only by Core's batch-v1 proof.
	 *
	 * @param WP_REST_Server $server Disposable server.
	 */
	public function registerBatchRoutes( WP_REST_Server $server ): void {
		$server->register_route(
			self::NAMESPACE,
			self::BATCH_PUBLIC_ROUTE,
			$this->handler( 'batch-public', true, 'POST' )
		);

		$server->register_route(
			self::NAMESPACE,
			self::BATCH_PROTECTED_ROUTE,
			ProtectedRouteRegistry::assign(
				$this->handler( 'batch-protected', true, 'POST' ),
				'batch-protected',
				SyntheticBearerFixtures::DEFAULT_RESOURCE,
				array( SyntheticBearerFixtures::GENERAL_SCOPE )
			)
		);
	}

	/**
	 * Returns the number of permission invocations.
	 */
	public function permissionCount(): int {
		return $this->permissionCount;
	}

	/**
	 * Returns the number of main callback invocations.
	 */
	public function callbackCount(): int {
		return $this->callbackCount;
	}

	/**
	 * Resets only the current worker's counters.
	 */
	public function resetCounts(): void {
		$this->permissionCount = 0;
		$this->callbackCount   = 0;
	}

	/**
	 * Creates one observable proof handler.
	 *
	 * @param string $label   Fixed route label.
	 * @param bool   $allowed Permission outcome.
	 * @param string $methods Exact HTTP methods.
	 * @return array<string, mixed>
	 */
	private function handler( string $label, bool $allowed, string $methods = 'GET' ): array {
		return array(
			'methods'             => $methods,
			'allow_batch'         => array( 'v1' => true ),
			'permission_callback' => function ( WP_REST_Request $request ) use ( $label, $allowed ): bool {
				++$this->permissionCount;
				$this->boundary->recordInvocation( $request, $label, 'permission', $allowed ? 'allowed' : 'denied' );

				return $allowed;
			},
			'callback'            => function ( WP_REST_Request $request ) use ( $label ): WP_REST_Response {
				++$this->callbackCount;
				$this->boundary->recordInvocation( $request, $label, 'callback', 'completed' );

				return new WP_REST_Response(
					array(
						'route'         => $label,
						'authenticated' => 0 < get_current_user_id(),
					),
					200
				);
			},
		);
	}
}
