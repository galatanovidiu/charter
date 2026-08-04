<?php
/**
 * Mixed WordPress and Bearer authentication boundary tests.
 *
 * @package GalatanOvidiu\Charter
 */

declare(strict_types=1);

namespace GalatanOvidiu\Charter\Tests\Integration\RestAuthenticationBoundary;

use GalatanOvidiu\Charter\Tests\Prototype\RestAuthenticationBoundary\ChallengeResponseProjector;
use GalatanOvidiu\Charter\Tests\Prototype\RestAuthenticationBoundary\InvocationLedger;
use GalatanOvidiu\Charter\Tests\Prototype\RestAuthenticationBoundary\ProtectedRouteRegistry;
use GalatanOvidiu\Charter\Tests\Prototype\RestAuthenticationBoundary\RequestContextStack;
use GalatanOvidiu\Charter\Tests\Prototype\RestAuthenticationBoundary\RestAuthenticationBoundary;
use GalatanOvidiu\Charter\Tests\Prototype\RestAuthenticationBoundary\SyntheticBearerFixtures;
use WP_REST_Request;
use WP_REST_Response;
use WP_REST_Server;
use WP_UnitTestCase;

/**
 * Proves the owner-approved mixed-authentication contract at the matched route.
 *
 * @since 0.1.0
 */
final class MixedAuthenticationBoundaryTest extends WP_UnitTestCase {

	private const NAMESPACE = 'charter-p2-mixed/v1';

	private const RESOURCE = 'https://site.test';

	private const RESOURCE_METADATA = 'https://site.test/.well-known/oauth-protected-resource';

	/**
	 * Disposable boundary under test.
	 *
	 * @var RestAuthenticationBoundary
	 */
	private RestAuthenticationBoundary $boundary;

	/**
	 * In-memory bearer cases.
	 *
	 * @var SyntheticBearerFixtures
	 */
	private SyntheticBearerFixtures $fixtures;

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
	 * Exact user active before the fixture.
	 *
	 * @var int
	 */
	private int $priorUserId = 0;

	/**
	 * Exact user represented by successful WordPress authentication.
	 *
	 * @var int
	 */
	private int $wordpressUserId;

	/**
	 * Protected permission callback count.
	 *
	 * @var int
	 */
	private int $permissionCalls = 0;

	/**
	 * Protected main callback count.
	 *
	 * @var int
	 */
	private int $callbackCalls = 0;

	/**
	 * Installs the proof boundary and its exact assigned/public routes.
	 */
	public function setUp(): void {
		parent::setUp();

		$userAId               = self::factory()->user->create( array( 'role' => 'author' ) );
		$this->wordpressUserId = self::factory()->user->create( array( 'role' => 'editor' ) );
		$this->priorUserId     = get_current_user_id();
		$this->priorServer     = isset( $GLOBALS['wp_rest_server'] ) && $GLOBALS['wp_rest_server'] instanceof WP_REST_Server
			? $GLOBALS['wp_rest_server']
			: null;
		$this->server          = new CapturingRestServer();
		$this->fixtures        = new SyntheticBearerFixtures( $userAId, $this->wordpressUserId );
		$this->boundary        = new RestAuthenticationBoundary(
			$this->fixtures->validator(),
			new RequestContextStack(),
			new InvocationLedger(),
			new ChallengeResponseProjector()
		);

		// phpcs:ignore WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedVariableFound -- Core-owned REST server global.
		$GLOBALS['wp_rest_server'] = $this->server;

		$this->registerRoutes();
		$this->boundary->install();
	}

	/**
	 * Removes proof hooks and restores Core globals.
	 */
	public function tearDown(): void {
		$this->boundary->remove();
		$this->boundary->reset();

		unset( $_SERVER['HTTP_X_WP_NONCE'] );
		// phpcs:ignore WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedVariableFound -- Resetting Core authentication state.
		$GLOBALS['wp_rest_auth_cookie'] = null;
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
	 * Proves any Bearer attempt after WordPress authentication is rejected first.
	 */
	public function testAssignedRouteRejectsWordPressAuthenticationCombinedWithAnyBearerAttemptBeforeValidation(): void {
		$this->establishWordPressCookieAuthentication();

		$cases = array(
			SyntheticBearerFixtures::CASE_VALID_A_DEFAULT,
			SyntheticBearerFixtures::CASE_UNKNOWN,
			SyntheticBearerFixtures::CASE_EXPIRED,
			SyntheticBearerFixtures::CASE_INSUFFICIENT_SCOPE,
			SyntheticBearerFixtures::CASE_MALFORMED,
		);

		foreach ( $cases as $case ) {
			$request = $this->request( '/protected' );
			$request->set_header( 'Authorization', $this->fixtures->authorizationHeader( $case ) );

			$response = $this->server->dispatch( $request );

			self::assertSame( 400, $response->get_status() );
			self::assertSame( 'invalid_request', $response->get_data()['code'] );
			self::assertSame(
				'Use either WordPress authentication or Bearer authentication, not both.',
				$response->get_data()['message']
			);
			self::assertSame(
				array(
					'error'             => 'invalid_request',
					'resource_metadata' => self::RESOURCE_METADATA,
				),
				self::parseBearerChallenge( $response )
			);
			self::assertSame( 0, $this->boundary->validator()->validationCount() );
			self::assertSame( $this->wordpressUserId, get_current_user_id() );
			self::assertSame( 0, $this->boundary->contexts()->depth() );
			self::assertNull( $this->boundary->contexts()->current() );
		}

		self::assertSame( 0, $this->permissionCalls );
		self::assertSame( 0, $this->callbackCalls );
	}

	/**
	 * Proves an unassigned public route ignores the same mixed input.
	 */
	public function testPublicRouteRemainsInertForWordPressAuthenticationAndBearerAttempt(): void {
		$this->establishWordPressCookieAuthentication();
		$request = $this->request( '/public' );
		$request->set_header(
			'Authorization',
			$this->fixtures->authorizationHeader( SyntheticBearerFixtures::CASE_VALID_A_DEFAULT )
		);

		$response = $this->server->dispatch( $request );

		self::assertSame( 200, $response->get_status() );
		self::assertSame(
			array(
				'public'  => true,
				'user_id' => $this->wordpressUserId,
			),
			$response->get_data()
		);
		self::assertArrayNotHasKey( 'WWW-Authenticate', $response->get_headers() );
		self::assertSame( 0, $this->boundary->validator()->validationCount() );
		self::assertSame( 0, $this->boundary->contexts()->depth() );
		self::assertSame( $this->wordpressUserId, get_current_user_id() );
	}

	/**
	 * Registers one assigned and one unassigned route.
	 */
	private function registerRoutes(): void {
		$protected = ProtectedRouteRegistry::assign(
			array(
				'methods'             => 'GET',
				'permission_callback' => function (): bool {
					++$this->permissionCalls;

					return true;
				},
				'callback'            => function (): array {
					++$this->callbackCalls;

					return array( 'protected' => true );
				},
			),
			'default_get',
			self::RESOURCE,
			array( 'wordpress:access' )
		);

		$this->server->register_route(
			self::NAMESPACE,
			'/' . self::NAMESPACE . '/protected',
			array( $protected )
		);
		$this->server->register_route(
			self::NAMESPACE,
			'/' . self::NAMESPACE . '/public',
			array(
				array(
					'methods'             => 'GET',
					'permission_callback' => '__return_true',
					'callback'            => function (): array {
						return array(
							'public'  => true,
							'user_id' => get_current_user_id(),
						);
					},
				),
			)
		);
	}

	/**
	 * Establishes a successful WordPress cookie/nonce identity.
	 */
	private function establishWordPressCookieAuthentication(): void {
		wp_set_current_user( $this->wordpressUserId );
		// phpcs:ignore WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedVariableFound -- Exercising Core cookie authentication.
		$GLOBALS['wp_rest_auth_cookie'] = true;
		$_SERVER['HTTP_X_WP_NONCE']     = wp_create_nonce( 'wp_rest' );

		self::assertTrue( $this->server->check_authentication() );
		self::assertSame( $this->wordpressUserId, get_current_user_id() );
	}

	/**
	 * Creates one request in the proof namespace.
	 *
	 * @param string $route Relative route.
	 */
	private function request( string $route ): WP_REST_Request {
		return new WP_REST_Request( 'GET', '/' . self::NAMESPACE . $route );
	}

	/**
	 * Parses a Bearer challenge independently of parameter order.
	 *
	 * @param WP_REST_Response $response REST response.
	 * @return array<string, string>
	 */
	private static function parseBearerChallenge( WP_REST_Response $response ): array {
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
