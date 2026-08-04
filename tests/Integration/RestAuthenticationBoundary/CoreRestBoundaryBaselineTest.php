<?php
/**
 * WordPress REST authentication-boundary baseline tests.
 *
 * @package GalatanOvidiu\Charter
 */

declare(strict_types=1);

namespace GalatanOvidiu\Charter\Tests\Integration\RestAuthenticationBoundary;

use WP_Application_Passwords;
use WP_Error;
use WP_REST_Request;
use WP_REST_Response;
use WP_REST_Server;
use WP_UnitTestCase;

/**
 * Freezes the Core-owned seams the disposable P2 boundary must preserve.
 *
 * @since 0.1.0
 */
final class CoreRestBoundaryBaselineTest extends WP_UnitTestCase {

	private const NAMESPACE = 'charter-p2-core/v1';

	/**
	 * Isolated REST server.
	 *
	 * @var WP_REST_Server
	 */
	private WP_REST_Server $server;

	/**
	 * Prior REST server.
	 *
	 * @var WP_REST_Server|null
	 */
	private ?WP_REST_Server $priorServer = null;

	/**
	 * Prior current-user ID.
	 *
	 * @var int
	 */
	private int $priorUserId = 0;

	/**
	 * Filters installed by the test.
	 *
	 * @var list<array{hook: string, callback: callable, priority: int}>
	 */
	private array $filters = array();

	/**
	 * Installs exact disposable globals.
	 */
	public function setUp(): void {
		parent::setUp();

		$this->priorServer = isset( $GLOBALS['wp_rest_server'] ) && $GLOBALS['wp_rest_server'] instanceof WP_REST_Server
			? $GLOBALS['wp_rest_server']
			: null;
		$this->priorUserId = get_current_user_id();
		$this->server      = new CapturingRestServer();

		// phpcs:ignore WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedVariableFound -- Core-owned REST server global.
		$GLOBALS['wp_rest_server'] = $this->server;
		$this->addFilter( 'rest_pre_dispatch', 'rest_handle_options_request', 3 );
	}

	/**
	 * Restores every exact disposable global.
	 */
	public function tearDown(): void {
		foreach ( array_reverse( $this->filters ) as $filter ) {
			remove_filter( $filter['hook'], $filter['callback'], $filter['priority'] );
		}

		unset( $_SERVER['HTTP_X_WP_NONCE'], $_SERVER['PHP_AUTH_USER'], $_SERVER['PHP_AUTH_PW'] );
		// phpcs:ignore WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedVariableFound -- Resetting Core authentication state.
		$GLOBALS['wp_rest_auth_cookie'] = null;
		// phpcs:ignore WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedVariableFound -- Resetting Core authentication state.
		$GLOBALS['wp_rest_application_password_status'] = null;
		wp_set_current_user( $this->priorUserId );

		if ( $this->priorServer instanceof WP_REST_Server ) {
			// phpcs:ignore WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedVariableFound -- Core-owned REST server global.
			$GLOBALS['wp_rest_server'] = $this->priorServer;
		} else {
			unset( $GLOBALS['wp_rest_server'] );
		}

		parent::tearDown();
	}

	/**
	 * Proves Core passes the exact dynamic/method handler before permission.
	 */
	public function testCoreSelectsDynamicMultiMethodAndHeadFallbackHandlersExactly(): void {
		$selected = array();
		$calls    = array();

		$this->addFilter(
			'rest_request_before_callbacks',
			static function ( $response, array $handler, WP_REST_Request $request ) use ( &$selected ) {
				$selected[] = array(
					'marker'   => $handler['proof_marker'] ?? null,
					'resource' => $handler['proof_resource'] ?? null,
					'id'       => $request->get_url_params()['id'] ?? null,
				);

				return $response;
			},
			3
		);

		$this->register(
			'/items/(?P<id>[\d]+)',
			array(
				$this->handler( 'GET', 'get', 'default-resource', $calls ),
				$this->handler( 'POST', 'post', 'isolated-resource', $calls ),
			)
		);

		foreach (
			array(
				array( 'GET', 'get', 'default-resource' ),
				array( 'POST', 'post', 'isolated-resource' ),
				array( 'HEAD', 'get', 'default-resource' ),
			) as $case
		) {
			$response = $this->dispatch( $case[0], '/items/37' );

			self::assertSame( 200, $response->get_status() );
			self::assertSame(
				array(
					'marker'   => $case[1],
					'resource' => $case[2],
					'id'       => '37',
				),
				array_shift( $selected )
			);
		}

		$options = $this->dispatch( 'OPTIONS', '/items/37' );
		$wrong   = $this->dispatch( 'DELETE', '/items/37' );

		self::assertSame( 200, $options->get_status() );
		self::assertSame( 404, $wrong->get_status() );
		self::assertSame( 'rest_no_route', $wrong->get_data()['code'] );
		self::assertSame( array(), $selected, 'OPTIONS or a wrong method entered the ordinary matched-handler seam.' );
		self::assertSame(
			array(
				'permission:get',
				'callback:get',
				'permission:post',
				'callback:post',
				'permission:get',
				'callback:get',
			),
			$calls
		);
	}

	/**
	 * Proves public behavior remains inert even with a Bearer-looking header.
	 */
	public function testPublicRouteBaselineIsInertWithBearerLookingHeader(): void {
		$callbackUser = -1;
		$this->register(
			'/public',
			array(
				array(
					'methods'             => 'GET',
					'permission_callback' => '__return_true',
					'callback'            => static function () use ( &$callbackUser ): array {
						$callbackUser = get_current_user_id();

						return array( 'public' => true );
					},
				),
			)
		);

		$request = $this->request( 'GET', '/public' );
		$request->set_header( 'Authorization', 'Bearer bearer-looking-public-value' );
		$response = $this->server->dispatch( $request );

		self::assertSame( 200, $response->get_status() );
		self::assertSame( array( 'public' => true ), $response->get_data() );
		self::assertSame( 0, $callbackUser );
		self::assertArrayNotHasKey( 'WWW-Authenticate', $response->get_headers() );
	}

	/**
	 * Proves valid, missing, and invalid REST nonces remain WordPress-owned.
	 */
	public function testCookieNonceAuthenticationRetainsCoreResultsBeforeRouteMatching(): void {
		$userId = self::factory()->user->create( array( 'role' => 'editor' ) );

		wp_set_current_user( $userId );
		// phpcs:ignore WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedVariableFound -- Exercising Core cookie authentication.
		$GLOBALS['wp_rest_auth_cookie'] = true;
		$_SERVER['HTTP_X_WP_NONCE']     = wp_create_nonce( 'wp_rest' );

		self::assertTrue( $this->server->check_authentication() );
		self::assertSame( $userId, get_current_user_id() );

		unset( $_SERVER['HTTP_X_WP_NONCE'] );
		wp_set_current_user( $userId );
		// phpcs:ignore WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedVariableFound -- Exercising Core cookie authentication.
		$GLOBALS['wp_rest_auth_cookie'] = true;

		self::assertTrue( $this->server->check_authentication() );
		self::assertSame( 0, get_current_user_id() );

		wp_set_current_user( $userId );
		// phpcs:ignore WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedVariableFound -- Exercising Core cookie authentication.
		$GLOBALS['wp_rest_auth_cookie'] = true;
		$_SERVER['HTTP_X_WP_NONCE']     = 'invalid-proof-nonce';
		$invalid                        = $this->server->check_authentication();

		self::assertInstanceOf( WP_Error::class, $invalid );
		self::assertSame( 'rest_cookie_invalid_nonce', $invalid->get_error_code() );
		self::assertSame( 403, $invalid->get_error_data()['status'] );
		self::assertSame( $userId, get_current_user_id() );
	}

	/**
	 * Proves Application Password success/failure remains WordPress-owned.
	 */
	public function testApplicationPasswordAuthenticationRetainsCoreResultsBeforeRouteMatching(): void {
		$userId  = self::factory()->user->create(
			array(
				'role'       => 'editor',
				'user_login' => 'charter_p2_app_password_user',
			)
		);
		$created = WP_Application_Passwords::create_new_application_password(
			$userId,
			array( 'name' => 'Charter P2 disposable proof' )
		);

		self::assertIsArray( $created );

		$this->addFilter( 'wp_is_application_passwords_available', '__return_true', 0 );
		$this->addFilter( 'application_password_is_api_request', '__return_true', 1 );
		$_SERVER['PHP_AUTH_USER'] = 'charter_p2_app_password_user';
		$_SERVER['PHP_AUTH_PW']   = $created[0];

		self::assertSame( $userId, wp_validate_application_password( false ) );
		self::assertTrue( $this->server->check_authentication() );

		// phpcs:ignore WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedVariableFound -- Resetting Core authentication state.
		$GLOBALS['wp_rest_application_password_status'] = null;
		$_SERVER['PHP_AUTH_PW']                         = 'invalid-disposable-proof-value';

		self::assertFalse( wp_validate_application_password( false ) );
		$invalid = $this->server->check_authentication();

		self::assertInstanceOf( WP_Error::class, $invalid );
		self::assertSame( 401, $invalid->get_error_data()['status'] );
	}

	/**
	 * Builds one method handler.
	 *
	 * @param string $method        HTTP method.
	 * @param string $marker        Handler marker.
	 * @param string $resourceLabel Assigned resource label.
	 * @param array  $calls         Shared callback ledger.
	 * @return array<string, mixed>
	 * @phpstan-param list<string> $calls
	 */
	private function handler( string $method, string $marker, string $resourceLabel, array &$calls ): array {
		return array(
			'methods'             => $method,
			'proof_marker'        => $marker,
			'proof_resource'      => $resourceLabel,
			'permission_callback' => static function () use ( &$calls, $marker ): bool {
				$calls[] = 'permission:' . $marker;

				return true;
			},
			'callback'            => static function () use ( &$calls, $marker ): array {
				$calls[] = 'callback:' . $marker;

				return array( 'marker' => $marker );
			},
		);
	}

	/**
	 * Registers one full route on the isolated server.
	 *
	 * @param string $route    Relative route.
	 * @param array  $handlers Route handlers.
	 * @phpstan-param list<array<string, mixed>> $handlers
	 */
	private function register( string $route, array $handlers ): void {
		$this->server->register_route(
			self::NAMESPACE,
			'/' . self::NAMESPACE . $route,
			$handlers
		);
	}

	/**
	 * Dispatches one request.
	 *
	 * @param string $method HTTP method.
	 * @param string $route  Relative route.
	 */
	private function dispatch( string $method, string $route ): WP_REST_Response {
		return $this->server->dispatch( $this->request( $method, $route ) );
	}

	/**
	 * Builds one request.
	 *
	 * @param string $method HTTP method.
	 * @param string $route  Relative route.
	 */
	private function request( string $method, string $route ): WP_REST_Request {
		return new WP_REST_Request( $method, '/' . self::NAMESPACE . $route );
	}

	/**
	 * Registers a disposable filter.
	 *
	 * @param string   $hook         Hook name.
	 * @param callable $callback     Hook callback.
	 * @param int      $acceptedArgs Accepted argument count.
	 */
	private function addFilter( string $hook, callable $callback, int $acceptedArgs ): void {
		add_filter( $hook, $callback, 10, $acceptedArgs );

		$this->filters[] = array(
			'hook'     => $hook,
			'callback' => $callback,
			'priority' => 10,
		);
	}
}
