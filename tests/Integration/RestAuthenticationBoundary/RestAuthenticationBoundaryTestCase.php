<?php
/**
 * Shared WordPress REST authentication-boundary test fixture.
 *
 * @package GalatanOvidiu\Charter
 */

declare(strict_types=1);

namespace GalatanOvidiu\Charter\Tests\Integration\RestAuthenticationBoundary;

use GalatanOvidiu\Charter\Tests\Prototype\RestAuthenticationBoundary\ProtectedRouteRegistry;
use GalatanOvidiu\Charter\Tests\Prototype\RestAuthenticationBoundary\RestAuthenticationBoundary;
use GalatanOvidiu\Charter\Tests\Prototype\RestAuthenticationBoundary\SyntheticBearerFixtures;
use WP_REST_Request;
use WP_REST_Response;
use WP_REST_Server;
use WP_UnitTestCase;

/**
 * Owns exact disposable users, server, routes, and proof hooks for one test.
 *
 * @since 0.1.0
 */
abstract class RestAuthenticationBoundaryTestCase extends WP_UnitTestCase {

	protected const NAMESPACE = 'charter-p2-boundary/v1';

	protected const DEFAULT_RESOURCE = SyntheticBearerFixtures::DEFAULT_RESOURCE;

	protected const ISOLATED_RESOURCE = SyntheticBearerFixtures::ISOLATED_RESOURCE;

	protected const DEFAULT_METADATA = 'https://charter.example.test/.well-known/oauth-protected-resource';

	protected const ISOLATED_METADATA = 'https://charter.example.test/.well-known/oauth-protected-resource/isolated';

	/**
	 * Disposable boundary.
	 *
	 * @var RestAuthenticationBoundary
	 */
	protected RestAuthenticationBoundary $boundary;

	/**
	 * Disposable bearer cases.
	 *
	 * @var SyntheticBearerFixtures
	 */
	protected SyntheticBearerFixtures $fixtures;

	/**
	 * Isolated REST server.
	 *
	 * @var WP_REST_Server
	 */
	protected WP_REST_Server $server;

	/**
	 * Bearer user A.
	 *
	 * @var int
	 */
	protected int $userAId;

	/**
	 * Bearer/legacy user B.
	 *
	 * @var int
	 */
	protected int $userBId;

	/**
	 * Prior server.
	 *
	 * @var WP_REST_Server|null
	 */
	private ?WP_REST_Server $priorServer = null;

	/**
	 * Prior user.
	 *
	 * @var int
	 */
	private int $priorUserId = 0;

	/**
	 * Installs one isolated proof boundary.
	 */
	public function setUp(): void {
		parent::setUp();

		$this->priorServer = isset( $GLOBALS['wp_rest_server'] ) && $GLOBALS['wp_rest_server'] instanceof WP_REST_Server
			? $GLOBALS['wp_rest_server']
			: null;
		$this->priorUserId = get_current_user_id();
		$this->userAId     = self::factory()->user->create( array( 'role' => 'administrator' ) );
		$this->userBId     = self::factory()->user->create( array( 'role' => 'subscriber' ) );
		$this->server      = new CapturingRestServer();
		$this->fixtures    = new SyntheticBearerFixtures( $this->userAId, $this->userBId );
		$this->boundary    = RestAuthenticationBoundary::fromFixtures( $this->fixtures );

		// phpcs:ignore WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedVariableFound -- Core-owned REST server global.
		$GLOBALS['wp_rest_server'] = $this->server;

		add_filter( 'rest_pre_dispatch', 'rest_handle_options_request', 10, 3 );
		$this->boundary->install();
	}

	/**
	 * Removes proof hooks and restores exact prior globals.
	 */
	public function tearDown(): void {
		$this->boundary->remove();
		$this->boundary->reset();
		remove_filter( 'rest_pre_dispatch', 'rest_handle_options_request', 10 );

		unset(
			$_SERVER['HTTP_X_WP_NONCE'],
			$_SERVER['PHP_AUTH_USER'],
			$_SERVER['PHP_AUTH_PW']
		);
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
	 * Decorates one assigned handler.
	 *
	 * @param array  $handler        WordPress REST handler.
	 * @param string $routeLabel     Stable route label.
	 * @param string $resourceLabel  Exact protected resource.
	 * @param array  $requiredScopes Complete required scopes.
	 * @return array<string, mixed>
	 * @phpstan-param array<string, mixed> $handler
	 * @phpstan-param list<string> $requiredScopes
	 */
	protected function assigned(
		array $handler,
		string $routeLabel,
		string $resourceLabel = self::DEFAULT_RESOURCE,
		array $requiredScopes = array( SyntheticBearerFixtures::GENERAL_SCOPE )
	): array {
		return ProtectedRouteRegistry::assign( $handler, $routeLabel, $resourceLabel, $requiredScopes );
	}

	/**
	 * Registers exact full route keys on the isolated server.
	 *
	 * @param string $route    Relative route.
	 * @param array  $handlers Route handlers.
	 * @phpstan-param list<array<string, mixed>> $handlers
	 */
	protected function register( string $route, array $handlers ): void {
		$this->server->register_route(
			self::NAMESPACE,
			'/' . self::NAMESPACE . $route,
			$handlers
		);
	}

	/**
	 * Creates one proof request.
	 *
	 * @param string $method HTTP method.
	 * @param string $route  Relative route.
	 */
	protected function request( string $method, string $route ): WP_REST_Request {
		return new WP_REST_Request( $method, '/' . self::NAMESPACE . $route );
	}

	/**
	 * Dispatches one proof request.
	 *
	 * @param WP_REST_Request $request REST request.
	 */
	protected function dispatch( WP_REST_Request $request ): WP_REST_Response {
		return $this->server->dispatch( $request );
	}

	/**
	 * Creates one authorized request without exposing its credential.
	 *
	 * @param string $method HTTP method.
	 * @param string $route  Relative route.
	 * @param string $fixtureCase Semantic fixture case.
	 */
	protected function authorizedRequest( string $method, string $route, string $fixtureCase ): WP_REST_Request {
		$request = $this->request( $method, $route );
		$this->fixtures->authorize( $request, $fixtureCase );

		return $request;
	}

	/**
	 * Requires complete proof identity/context cleanup.
	 *
	 * @param int $userId Expected restored user.
	 */
	protected function assertProofStateClean( int $userId = 0 ): void {
		self::assertSame( $userId, get_current_user_id() );
		self::assertSame( 0, $this->boundary->contexts()->depth() );
		self::assertNull( $this->boundary->contexts()->current() );
	}

	/**
	 * Parses a Bearer challenge independently of parameter order.
	 *
	 * @param WP_REST_Response $response REST response.
	 * @return array<string, string>
	 */
	protected static function parseBearerChallenge( WP_REST_Response $response ): array {
		$headers = $response->get_headers();

		self::assertArrayHasKey( 'WWW-Authenticate', $headers );
		self::assertStringStartsWith( 'Bearer ', $headers['WWW-Authenticate'] );
		preg_match_all(
			'/([a-z_]+)="([^"]*)"/',
			$headers['WWW-Authenticate'],
			$matches,
			PREG_SET_ORDER
		);

		$parameters = array();
		foreach ( $matches as $match ) {
			$parameters[ $match[1] ] = $match[2];
		}

		ksort( $parameters );

		return $parameters;
	}
}
