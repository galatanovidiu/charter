<?php
/**
 * WordPress REST authentication-boundary cleanup tests.
 *
 * @package GalatanOvidiu\Charter
 */

declare(strict_types=1);

namespace GalatanOvidiu\Charter\Tests\Integration\RestAuthenticationBoundary;

use GalatanOvidiu\Charter\Tests\Prototype\RestAuthenticationBoundary\BearerValidationResult;
use GalatanOvidiu\Charter\Tests\Prototype\RestAuthenticationBoundary\SyntheticBearerFixtures;
use RuntimeException;
use WP_Error;
use WP_REST_Request;
use WP_REST_Response;

/**
 * Proves request-keyed cleanup across every in-process dispatch form.
 *
 * @since 0.1.0
 */
final class RestAuthenticationBoundaryCleanupTest extends RestAuthenticationBoundaryTestCase {

	/**
	 * Proves post-dispatch-only cleanup leaks under direct dispatch.
	 */
	public function testIncompletePostDispatchOnlyCandidateLeaksDirectDispatchIdentity(): void {
		$callbackUser = 0;
		$this->register(
			'/incomplete-cleanup',
			array(
				$this->assigned(
					array(
						'methods'             => 'GET',
						'permission_callback' => '__return_true',
						'callback'            => static function () use ( &$callbackUser ): array {
							$callbackUser = get_current_user_id();

							return array( 'leak_observed' => true );
						},
					),
					'incomplete_cleanup_get'
				),
			)
		);

		$this->boundary->remove();
		add_filter( 'rest_request_before_callbacks', array( $this->boundary, 'beforeCallbacks' ), 10, 3 );
		add_filter( 'rest_post_dispatch', array( $this->boundary, 'sendAllowHeader' ), 10, 3 );
		try {
			$response = $this->dispatch(
				$this->authorizedRequest( 'GET', '/incomplete-cleanup', SyntheticBearerFixtures::CASE_VALID_A_DEFAULT )
			);
			self::assertSame( 200, $response->get_status() );
			self::assertSame( $this->userAId, $callbackUser );
			self::assertSame( $this->userAId, get_current_user_id() );
			self::assertSame( 1, $this->boundary->contexts()->depth() );
			self::assertSame( self::DEFAULT_RESOURCE, $this->boundary->contexts()->current()?->resource() );
		} finally {
			remove_filter( 'rest_request_before_callbacks', array( $this->boundary, 'beforeCallbacks' ), 10 );
			remove_filter( 'rest_post_dispatch', array( $this->boundary, 'sendAllowHeader' ), 10 );
			$this->boundary->reset();
			$this->boundary->install();
		}

		$this->assertProofStateClean();
	}

	/**
	 * Proves direct sequential success/failure/error requests cannot inherit state.
	 */
	public function testSequentialDirectDispatchRestoresIdentityAcrossSuccessAndReturnedErrors(): void {
		$callbackUsers = array();
		$this->registerStandardRoutes( $callbackUsers );

		$sequence = array(
			array( 'protected', SyntheticBearerFixtures::CASE_VALID_A_DEFAULT, 200, $this->userAId ),
			array( 'public', null, 200, 0 ),
			array( 'protected', SyntheticBearerFixtures::CASE_VALID_B_DEFAULT, 200, $this->userBId ),
			array( 'protected', SyntheticBearerFixtures::CASE_UNKNOWN, 401, null ),
			array( 'returned-error', SyntheticBearerFixtures::CASE_VALID_A_DEFAULT, 422, $this->userAId ),
			array( 'public', null, 200, 0 ),
		);

		foreach ( $sequence as $step ) {
			$request  = null === $step[1]
				? $this->request( 'GET', '/' . $step[0] )
				: $this->authorizedRequest( 'GET', '/' . $step[0], $step[1] );
			$response = $this->dispatch( $request );

			self::assertSame( $step[2], $response->get_status() );
			$this->assertProofStateClean();
		}

		self::assertSame(
			array( $this->userAId, 0, $this->userBId, $this->userAId, 0 ),
			$callbackUsers
		);
	}

	/**
	 * Proves nested Bearer dispatch uses LIFO context rather than mixed-auth rejection.
	 */
	public function testNestedDispatchRestoresInnerUserToOuterBearerThenOuterToPriorUser(): void {
		$observations = array();
		$this->register(
			'/inner',
			array(
				$this->assigned(
					array(
						'methods'             => 'GET',
						'permission_callback' => function () use ( &$observations ): bool {
							$observations['inner_permission'] = $this->contextObservation();

							return true;
						},
						'callback'            => function () use ( &$observations ): array {
							$observations['inner_callback'] = $this->contextObservation();

							return array( 'inner' => true );
						},
					),
					'inner_get'
				),
			)
		);
		$this->register(
			'/outer',
			array(
				$this->assigned(
					array(
						'methods'             => 'GET',
						'permission_callback' => '__return_true',
						'callback'            => function () use ( &$observations ): array {
							$observations['outer_before_inner'] = $this->contextObservation();
							$inner = $this->dispatch(
								$this->authorizedRequest( 'GET', '/inner', SyntheticBearerFixtures::CASE_VALID_B_DEFAULT )
							);
							$observations['inner_status']       = $inner->get_status();
							$observations['outer_after_inner']  = $this->contextObservation();

							return array( 'outer' => true );
						},
					),
					'outer_get'
				),
			)
		);

		$response = $this->dispatch(
			$this->authorizedRequest( 'GET', '/outer', SyntheticBearerFixtures::CASE_VALID_A_DEFAULT )
		);

		self::assertSame( 200, $response->get_status() );
		self::assertSame( 200, $observations['inner_status'] );
		self::assertSame( $this->userAId, $observations['outer_before_inner']['user_id'] );
		self::assertSame( 1, $observations['outer_before_inner']['depth'] );
		self::assertSame( $this->userBId, $observations['inner_permission']['user_id'] );
		self::assertSame( 2, $observations['inner_permission']['depth'] );
		self::assertSame( $observations['inner_permission'], $observations['inner_callback'] );
		self::assertSame( $observations['outer_before_inner'], $observations['outer_after_inner'] );
		$this->assertProofStateClean();
	}

	/**
	 * Proves Core's batch implementation isolates every inner request.
	 */
	public function testBatchInnerRequestsCannotInheritIdentityContextOrFailure(): void {
		$callbackUsers = array();
		$this->registerStandardRoutes( $callbackUsers );

		$batch = new WP_REST_Request( 'POST', '/batch/v1' );
		$batch->set_body_params(
			array(
				'requests' => array(
					$this->batchItem( '/protected', SyntheticBearerFixtures::CASE_VALID_A_DEFAULT ),
					$this->batchItem( '/public' ),
					$this->batchItem( '/protected', SyntheticBearerFixtures::CASE_UNKNOWN ),
					$this->batchItem( '/protected', SyntheticBearerFixtures::CASE_VALID_B_DEFAULT ),
					$this->batchItem( '/public' ),
				),
			)
		);

		$response  = $this->dispatch( $batch );
		$responses = $response->get_data()['responses'];

		self::assertSame( 207, $response->get_status() );
		self::assertSame( array( 200, 200, 401, 200, 200 ), array_column( $responses, 'status' ) );
		self::assertSame( array( $this->userAId, 0, $this->userBId, 0 ), $callbackUsers );
		$this->assertProofStateClean();
	}

	/**
	 * Proves direct dispatch cleanup and later Allow recheck identity coexist.
	 */
	public function testPostDispatchAllowRechecksPermissionsUnderBearerThenRestoresIdentity(): void {
		$permissionObservations = array();
		$get                    = $this->assigned(
			array(
				'methods'             => 'GET',
				'permission_callback' => function () use ( &$permissionObservations ): bool {
					$permissionObservations[] = array( 'method' => 'GET' ) + $this->contextObservation();

					return get_current_user_id() === $this->userAId;
				},
				'callback'            => static fn (): array => array( 'method' => 'GET' ),
			),
			'multi_get'
		);
		$post                   = $this->assigned(
			array(
				'methods'             => 'POST',
				'permission_callback' => function () use ( &$permissionObservations ): bool {
					$permissionObservations[] = array( 'method' => 'POST' ) + $this->contextObservation();

					return true;
				},
				'callback'            => static fn (): array => array( 'method' => 'POST' ),
			),
			'multi_post',
			self::ISOLATED_RESOURCE
		);
		$this->register( '/multi', array( $get, $post ) );

		$request  = $this->authorizedRequest( 'GET', '/multi', SyntheticBearerFixtures::CASE_VALID_A_DEFAULT );
		$response = $this->dispatch( $request );

		self::assertSame( 200, $response->get_status() );
		self::assertArrayNotHasKey( 'Allow', $response->get_headers() );
		$this->assertProofStateClean();

		$incomplete = rest_send_allow_header( $response, $this->server, $request );
		self::assertSame( 'POST', $incomplete->get_headers()['Allow'] );
		$this->assertProofStateClean();

		// phpcs:ignore WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedHooknameFound -- Exercising the installed protected Allow pass.
		$response = apply_filters( 'rest_post_dispatch', $response, $this->server, $request );

		self::assertInstanceOf( WP_REST_Response::class, $response );
		self::assertSame( 'GET', $response->get_headers()['Allow'] );
		self::assertSame( array( 'GET', 'GET', 'POST', 'GET' ), array_column( $permissionObservations, 'method' ) );
		self::assertSame( $this->userAId, $permissionObservations[0]['user_id'] );
		self::assertSame( self::DEFAULT_RESOURCE, $permissionObservations[0]['resource'] );
		self::assertSame( 1, $permissionObservations[0]['depth'] );
		foreach ( array( 1, 2 ) as $index ) {
			self::assertSame( 0, $permissionObservations[ $index ]['user_id'] );
			self::assertNull( $permissionObservations[ $index ]['resource'] );
			self::assertSame( 0, $permissionObservations[ $index ]['depth'] );
		}
		self::assertSame( $permissionObservations[0], $permissionObservations[3] );
		$this->assertProofStateClean();

		$postRequest  = $this->authorizedRequest( 'POST', '/multi', SyntheticBearerFixtures::CASE_VALID_A_ISOLATED );
		$postResponse = $this->dispatch( $postRequest );
		// phpcs:ignore WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedHooknameFound -- Exercising the installed protected Allow pass.
		$postResponse = apply_filters( 'rest_post_dispatch', $postResponse, $this->server, $postRequest );
		self::assertSame( 200, $postResponse->get_status() );
		self::assertSame( 'POST', $postResponse->get_headers()['Allow'] );
		self::assertSame( array( 'POST', 'POST' ), array_slice( array_column( $permissionObservations, 'method' ), -2 ) );
		self::assertSame( self::ISOLATED_RESOURCE, $permissionObservations[4]['resource'] );
		self::assertSame( $permissionObservations[4], $permissionObservations[5] );
		$this->assertProofStateClean();

		$headRequest  = $this->authorizedRequest( 'HEAD', '/multi', SyntheticBearerFixtures::CASE_VALID_A_DEFAULT );
		$headResponse = $this->dispatch( $headRequest );
		// phpcs:ignore WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedHooknameFound -- Exercising the installed protected Allow pass.
		$headResponse = apply_filters( 'rest_post_dispatch', $headResponse, $this->server, $headRequest );
		self::assertSame( 200, $headResponse->get_status() );
		self::assertSame( 'GET', $headResponse->get_headers()['Allow'] );
		self::assertSame( array( 'GET', 'GET' ), array_slice( array_column( $permissionObservations, 'method' ), -2 ) );
		$this->assertProofStateClean();
	}

	/**
	 * Proves an Allow permission throwable cannot strand identity or context.
	 */
	public function testPostDispatchAllowThrowableRestoresIdentityAndContext(): void {
		$this->register(
			'/allow-throw',
			array(
				$this->assigned(
					array(
						'methods'             => 'GET',
						'permission_callback' => '__return_true',
						'callback'            => static fn (): array => array( 'method' => 'GET' ),
					),
					'allow_throw_get'
				),
				$this->assigned(
					array(
						'methods'             => 'POST',
						'permission_callback' => static function (): bool {
							throw new RuntimeException( 'proof_allow_throwable' );
						},
						'callback'            => static fn (): array => array( 'method' => 'POST' ),
					),
					'allow_throw_post'
				),
			)
		);

		$request  = $this->authorizedRequest( 'GET', '/allow-throw', SyntheticBearerFixtures::CASE_VALID_A_DEFAULT );
		$response = $this->dispatch( $request );
		$this->assertProofStateClean();

		try {
			// phpcs:ignore WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedHooknameFound -- Exercising the installed protected Allow pass.
			apply_filters( 'rest_post_dispatch', $response, $this->server, $request );
			self::fail( 'Expected the disposable Allow permission throwable.' );
		} catch ( RuntimeException $exception ) {
			self::assertSame( 'proof_allow_throwable', $exception->getMessage() );
		}

		$this->assertProofStateClean();
	}

	/**
	 * Proves a bounded try/finally dispatch wrapper restores caught throwables.
	 */
	public function testThrowableSafeDispatchRestoresExactPriorIdentityAndContext(): void {
		$callbackObservation = array();
		$this->register(
			'/throwable',
			array(
				$this->assigned(
					array(
						'methods'             => 'GET',
						'permission_callback' => '__return_true',
						'callback'            => function () use ( &$callbackObservation ): array {
							$callbackObservation = $this->contextObservation();

							throw new RuntimeException( 'proof_callback_throwable' );
						},
					),
					'throwable_get'
				),
			)
		);

		try {
			$this->boundary->dispatchExceptionSafely(
				$this->server,
				$this->authorizedRequest( 'GET', '/throwable', SyntheticBearerFixtures::CASE_VALID_A_DEFAULT )
			);
			self::fail( 'Expected the disposable callback throwable.' );
		} catch ( RuntimeException $exception ) {
			self::assertSame( 'proof_callback_throwable', $exception->getMessage() );
		}

		self::assertSame( $this->userAId, $callbackObservation['user_id'] );
		self::assertSame( self::DEFAULT_RESOURCE, $callbackObservation['resource'] );
		self::assertSame( 1, $callbackObservation['depth'] );
		$this->assertProofStateClean();
	}

	/**
	 * Registers public, successful protected, and returned-error routes.
	 *
	 * @param array $callbackUsers Shared callback user ledger.
	 * @phpstan-param list<int> $callbackUsers
	 */
	private function registerStandardRoutes( array &$callbackUsers ): void {
		$this->register(
			'/public',
			array(
				array(
					'methods'             => 'GET,POST',
					'allow_batch'         => array( 'v1' => true ),
					'permission_callback' => '__return_true',
					'callback'            => static function () use ( &$callbackUsers ): array {
						$callbackUsers[] = get_current_user_id();

						return array( 'public' => true );
					},
				),
			)
		);
		$this->register(
			'/protected',
			array(
				$this->assigned(
					array(
						'methods'             => 'GET,POST',
						'allow_batch'         => array( 'v1' => true ),
						'permission_callback' => '__return_true',
						'callback'            => static function () use ( &$callbackUsers ): array {
							$callbackUsers[] = get_current_user_id();

							return array( 'protected' => true );
						},
					),
					'protected_get'
				),
			)
		);
		$this->register(
			'/returned-error',
			array(
				$this->assigned(
					array(
						'methods'             => 'GET',
						'permission_callback' => '__return_true',
						'callback'            => static function () use ( &$callbackUsers ): WP_Error {
							$callbackUsers[] = get_current_user_id();

							return new WP_Error( 'proof_returned_error', 'Returned proof error.', array( 'status' => 422 ) );
						},
					),
					'returned_error_get'
				),
			)
		);
	}

	/**
	 * Creates one batch inner request without retaining raw material in assertions.
	 *
	 * @param string      $route       Relative route.
	 * @param string|null $fixtureCase Optional semantic Bearer case.
	 * @return array<string, mixed>
	 */
	private function batchItem( string $route, ?string $fixtureCase = null ): array {
		$item = array(
			'method' => 'POST',
			'path'   => '/' . self::NAMESPACE . $route,
		);

		if ( null !== $fixtureCase ) {
			$item['headers'] = array(
				'Authorization' => $this->fixtures->authorizationHeader( $fixtureCase ),
			);
		}

		return $item;
	}

	/**
	 * Returns the current sanitized proof context.
	 *
	 * @return array{user_id: int, resource: string|null, depth: int}
	 */
	private function contextObservation(): array {
		$context = $this->boundary->contexts()->current();

		return array(
			'user_id'  => get_current_user_id(),
			'resource' => $context instanceof BearerValidationResult ? $context->resource() : null,
			'depth'    => $this->boundary->contexts()->depth(),
		);
	}
}
