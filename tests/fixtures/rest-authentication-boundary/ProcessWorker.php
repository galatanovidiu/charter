<?php
/**
 * One fresh-process or reused-process Slice 0 P2 worker.
 *
 * Run through `wp eval-file`; the outer runner retains and validates its output
 * privately before emitting a separate fixed result.
 *
 * @package GalatanOvidiu\Charter
 */

declare(strict_types=1);

namespace GalatanOvidiu\Charter\Tests\Fixtures\RestAuthenticationBoundary;

use GalatanOvidiu\Charter\Tests\Prototype\RestAuthenticationBoundary\BearerValidationResult;
use GalatanOvidiu\Charter\Tests\Prototype\RestAuthenticationBoundary\ProtectedRouteRegistry;
use GalatanOvidiu\Charter\Tests\Prototype\RestAuthenticationBoundary\RestAuthenticationBoundary;
use GalatanOvidiu\Charter\Tests\Prototype\RestAuthenticationBoundary\SyntheticBearerFixtures;
use RuntimeException;
use Throwable;
use WP_Application_Passwords;
use WP_Error;
use WP_REST_Request;
use WP_REST_Response;
use WP_REST_Server;

require_once dirname( __DIR__, 3 ) . '/vendor/autoload.php';
require_once __DIR__ . '/FixtureContract.php';
require_once __DIR__ . '/WorkerContract.php';
require_once __DIR__ . '/ProofRoutes.php';
require_once __DIR__ . '/ChallengeParser.php';

/**
 * Executes one isolated scenario without exposing fixture credentials.
 */
final class ProcessWorkerScenario {

	private const RESOURCE_METADATA = 'https://charter.example.test/.well-known/oauth-protected-resource';

	/**
	 * Runs one fixed worker mode.
	 *
	 * @param string $mode      Worker mode.
	 * @param int    $user_a_id Bearer user.
	 * @param int    $user_b_id Legacy user.
	 * @return array<string, bool>
	 * @throws RuntimeException For the deliberate sanitized-failure probe.
	 */
	public static function run( string $mode, int $user_a_id, int $user_b_id ): array {
		if ( 'failure-output' === $mode ) {
			// phpcs:ignore WordPress.Security.EscapeOutput.ExceptionNotEscaped -- The outer worker contract intentionally suppresses every marker.
			throw new RuntimeException( implode( '|', WorkerContract::PRIVATE_FAILURE_MARKERS ) );
		}

		return 'reused' === $mode
			? self::runReused( $user_a_id, $user_b_id )
			: self::runSingle( $mode, $user_a_id, $user_b_id );
	}

	/**
	 * Runs one isolated direct-dispatch scenario.
	 *
	 * @param string $mode      Worker mode.
	 * @param int    $user_a_id Bearer user.
	 * @param int    $user_b_id Legacy user.
	 * @return array<string, bool>
	 */
	private static function runSingle( string $mode, int $user_a_id, int $user_b_id ): array {
		$fixtures = new SyntheticBearerFixtures( $user_a_id, $user_b_id );
		$boundary = RestAuthenticationBoundary::fromFixtures( $fixtures );
		$routes   = new ProofRoutes( $boundary );
		$server   = rest_get_server();
		$prior    = get_current_user_id();

		$boundary->install();
		$routes->register( $server );

		try {
			if ( 'bearer-only' === $mode ) {
				wp_set_current_user( 0 );
				$request = new WP_REST_Request( 'GET', ProofRoutes::PROTECTED_ROUTE );
				$fixtures->authorize( $request, SyntheticBearerFixtures::CASE_VALID_A_DEFAULT );
				$response = $server->dispatch( $request );

				return self::checks(
					$response instanceof WP_REST_Response && 200 === $response->get_status(),
					1 === $boundary->validator()->validationCount(),
					1 === $routes->permissionCount() && 1 === $routes->callbackCount(),
					0 === get_current_user_id(),
					0 === $boundary->contexts()->depth()
				);
			}

			if ( 'error-matrix' === $mode ) {
				wp_set_current_user( 0 );
				$missing       = $server->dispatch( new WP_REST_Request( 'GET', ProofRoutes::PROTECTED_ROUTE ) );
				$responsesPass = self::hasCode( $missing, 401, 'rest_not_logged_in' );

				$invalidCases = array(
					SyntheticBearerFixtures::CASE_EXPIRED,
					SyntheticBearerFixtures::CASE_REVOKED,
					SyntheticBearerFixtures::CASE_UNKNOWN,
					SyntheticBearerFixtures::CASE_WRONG_ISSUER,
					SyntheticBearerFixtures::CASE_WRONG_RESOURCE,
					SyntheticBearerFixtures::CASE_WRONG_CLIENT,
					SyntheticBearerFixtures::CASE_WRONG_USER,
					SyntheticBearerFixtures::CASE_WRONG_GRANT,
					SyntheticBearerFixtures::CASE_POLICY_DENIED,
					SyntheticBearerFixtures::CASE_MALFORMED,
				);
				foreach ( $invalidCases as $fixtureCase ) {
					$invalidRequest = new WP_REST_Request( 'GET', ProofRoutes::PROTECTED_ROUTE );
					$fixtures->authorize( $invalidRequest, $fixtureCase );
					$invalidPassed = self::hasCode( $server->dispatch( $invalidRequest ), 401, 'invalid_token' );
					$responsesPass = $invalidPassed && $responsesPass;
				}

				$transportRequests = array();
				$malformed         = new WP_REST_Request( 'GET', ProofRoutes::PROTECTED_ROUTE );
				$malformed->set_header( 'Authorization', 'Bearer' );
				$transportRequests[] = $malformed;
				$query               = new WP_REST_Request( 'GET', ProofRoutes::PROTECTED_ROUTE );
				$query->set_query_params( array( 'access_token' => 'alternate-proof-value' ) );
				$transportRequests[] = $query;
				$body                = new WP_REST_Request( 'GET', ProofRoutes::PROTECTED_ROUTE );
				$body->set_body_params( array( 'access_token' => 'alternate-proof-value' ) );
				$transportRequests[] = $body;
				$json                = new WP_REST_Request( 'GET', ProofRoutes::PROTECTED_ROUTE );
				$json->set_header( 'Content-Type', 'application/json' );
				$json->set_body( '{"access_token":"alternate-proof-value"}' );
				$transportRequests[] = $json;
				$alternateHeader     = new WP_REST_Request( 'GET', ProofRoutes::PROTECTED_ROUTE );
				$alternateHeader->set_header( 'X-Charter-Access-Token', 'alternate-proof-value' );
				$transportRequests[] = $alternateHeader;
				$mixedTransport      = new WP_REST_Request( 'GET', ProofRoutes::PROTECTED_ROUTE );
				$fixtures->authorize( $mixedTransport, SyntheticBearerFixtures::CASE_VALID_A_DEFAULT );
				$mixedTransport->set_query_params( array( 'access_token' => 'alternate-proof-value' ) );
				$transportRequests[] = $mixedTransport;
				$duplicate           = new WP_REST_Request( 'GET', ProofRoutes::PROTECTED_ROUTE );
				$duplicate->add_header( 'Authorization', 'Bearer first-proof-value' );
				$duplicate->add_header( 'Authorization', 'Bearer second-proof-value' );
				$transportRequests[] = $duplicate;
				foreach ( $transportRequests as $transportRequest ) {
					$transportPassed = self::hasCode( $server->dispatch( $transportRequest ), 400, 'invalid_request' );
					$responsesPass   = $transportPassed && $responsesPass;
				}

				$scopeRequest = new WP_REST_Request( 'GET', ProofRoutes::PROTECTED_ROUTE );
				$fixtures->authorize( $scopeRequest, SyntheticBearerFixtures::CASE_INSUFFICIENT_SCOPE );
				$scope         = $server->dispatch( $scopeRequest );
				$deniedRequest = new WP_REST_Request( 'GET', ProofRoutes::DENIED_ROUTE );
				$fixtures->authorize( $deniedRequest, SyntheticBearerFixtures::CASE_VALID_A_DEFAULT );
				$denied = $server->dispatch( $deniedRequest );

				return self::checks(
					$responsesPass
						&& self::hasCode( $scope, 403, 'insufficient_scope' )
						&& self::hasCode( $denied, 403, 'rest_forbidden' ),
					19 === $boundary->validator()->validationCount(),
					1 === $routes->permissionCount() && 0 === $routes->callbackCount(),
					0 === get_current_user_id(),
					0 === $boundary->contexts()->depth()
				);
			}

			if ( 'legacy-only' === $mode ) {
				wp_set_current_user( $user_b_id );
				// phpcs:ignore WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedVariableFound -- Exercises Core cookie authentication.
				$GLOBALS['wp_rest_auth_cookie'] = true;
				$_SERVER['HTTP_X_WP_NONCE']     = wp_create_nonce( 'wp_rest' );
				$cookieAuthenticated            = true === $server->check_authentication();
				$cookieResponse                 = $server->dispatch( new WP_REST_Request( 'GET', ProofRoutes::PROTECTED_ROUTE ) );

				unset( $_SERVER['HTTP_X_WP_NONCE'] );
				// phpcs:ignore WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedVariableFound -- Resets Core cookie authentication.
				$GLOBALS['wp_rest_auth_cookie'] = null;
				wp_set_current_user( 0 );

				$application = WP_Application_Passwords::create_new_application_password(
					$user_b_id,
					array( 'name' => 'Charter P2 process proof' )
				);
				if ( ! is_array( $application ) || ! is_string( $application[0] ?? null ) ) {
					return self::checks( false, false, false, false, false );
				}

				add_filter( 'wp_is_application_passwords_available', '__return_true' );
				add_filter( 'application_password_is_api_request', '__return_true' );
				try {
					$user = get_userdata( $user_b_id );
					if ( false === $user ) {
						return self::checks( false, false, false, false, false );
					}
					$_SERVER['PHP_AUTH_USER'] = $user->user_login;
					$_SERVER['PHP_AUTH_PW']   = $application[0];
					$validatedUserId          = wp_validate_application_password( false );
					wp_set_current_user( is_int( $validatedUserId ) ? $validatedUserId : 0 );
					$appAuthenticated = true === $server->check_authentication();
					$appResponse      = $server->dispatch( new WP_REST_Request( 'GET', ProofRoutes::PROTECTED_ROUTE ) );
				} finally {
					remove_filter( 'wp_is_application_passwords_available', '__return_true' );
					remove_filter( 'application_password_is_api_request', '__return_true' );
					unset( $_SERVER['PHP_AUTH_USER'], $_SERVER['PHP_AUTH_PW'] );
					// phpcs:ignore WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedVariableFound -- Resets Core Application Password status.
					$GLOBALS['wp_rest_application_password_status'] = null;
					WP_Application_Passwords::delete_all_application_passwords( $user_b_id );
				}

				wp_set_current_user( $user_b_id );
				// phpcs:ignore WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedVariableFound -- Exercises Core missing-nonce behavior.
				$GLOBALS['wp_rest_auth_cookie'] = true;
				$missingNonceAuthenticated      = true === $server->check_authentication() && 0 === get_current_user_id();
				$bearerRequest                  = new WP_REST_Request( 'GET', ProofRoutes::PROTECTED_ROUTE );
				$fixtures->authorize( $bearerRequest, SyntheticBearerFixtures::CASE_VALID_A_DEFAULT );
				$missingNonceBearer = $server->dispatch( $bearerRequest );

				return self::checks(
					$cookieAuthenticated
						&& self::hasStatus( $cookieResponse, 200 )
						&& $appAuthenticated
						&& self::hasStatus( $appResponse, 200 )
						&& $missingNonceAuthenticated
						&& self::hasStatus( $missingNonceBearer, 200 ),
					1 === $boundary->validator()->validationCount(),
					3 === $routes->permissionCount() && 3 === $routes->callbackCount(),
					0 === get_current_user_id(),
					0 === $boundary->contexts()->depth()
				);
			}

			if ( 'direct-served-direct' === $mode ) {
				wp_set_current_user( 0 );
				$firstRequest = new WP_REST_Request( 'GET', ProofRoutes::PROTECTED_ROUTE );
				$fixtures->authorize( $firstRequest, SyntheticBearerFixtures::CASE_VALID_A_DEFAULT );
				$first      = $server->dispatch( $firstRequest );
				$firstClean = 0 === get_current_user_id() && 0 === $boundary->contexts()->depth();

				$_SERVER['REQUEST_METHOD']     = 'GET';
				$_SERVER['HTTP_AUTHORIZATION'] = $fixtures->authorizationHeader( SyntheticBearerFixtures::CASE_VALID_B_DEFAULT );
				ob_start();
				$server->serve_request( ProofRoutes::PROTECTED_ROUTE );
				$servedBody = ob_get_clean();
				unset( $_SERVER['HTTP_AUTHORIZATION'] );
				$served      = is_string( $servedBody ) ? json_decode( $servedBody, true ) : null;
				$servedClean = 0 === get_current_user_id() && 0 === $boundary->contexts()->depth();

				$last = $server->dispatch( new WP_REST_Request( 'GET', ProofRoutes::PUBLIC_ROUTE ) );

				return self::checks(
					$first instanceof WP_REST_Response
						&& 200 === $first->get_status()
						&& is_array( $served )
						&& 'protected' === ( $served['route'] ?? null )
						&& true === ( $served['authenticated'] ?? null )
						&& $last instanceof WP_REST_Response
						&& 200 === $last->get_status(),
					3 === $boundary->validator()->validationCount(),
					4 === $routes->permissionCount() && 3 === $routes->callbackCount(),
					$firstClean && $servedClean && 0 === get_current_user_id(),
					0 === $boundary->contexts()->depth()
				);
			}

			if ( 'route-matrix' === $mode ) {
				return self::runRouteMatrix( $server, $boundary, $fixtures, $routes, $user_a_id );
			}

			if ( 'cleanup-matrix' === $mode ) {
				return self::runCleanupMatrix( $server, $boundary, $fixtures, $routes, $user_a_id );
			}

			wp_set_current_user( $user_b_id );
			$route   = 'mixed' === $mode ? ProofRoutes::PROTECTED_ROUTE : ProofRoutes::PUBLIC_ROUTE;
			$request = new WP_REST_Request( 'GET', $route );
			$fixtures->authorize( $request, SyntheticBearerFixtures::CASE_VALID_A_DEFAULT );
			$response = $server->dispatch( $request );

			if ( 'mixed' === $mode ) {
				return self::checks(
					self::isMixedRejection( $response ),
					0 === $boundary->validator()->validationCount(),
					0 === $routes->permissionCount() && 0 === $routes->callbackCount(),
					get_current_user_id() === $user_b_id,
					0 === $boundary->contexts()->depth()
				);
			}

			return self::checks(
				$response instanceof WP_REST_Response
					&& 200 === $response->get_status()
					&& '' === (string) ( $response->get_headers()['WWW-Authenticate'] ?? '' ),
				0 === $boundary->validator()->validationCount(),
				1 === $routes->permissionCount() && 1 === $routes->callbackCount(),
				get_current_user_id() === $user_b_id,
				0 === $boundary->contexts()->depth()
			);
		} finally {
			$boundary->remove();
			unset( $_SERVER['HTTP_X_WP_NONCE'], $_SERVER['HTTP_AUTHORIZATION'], $_SERVER['PHP_AUTH_USER'], $_SERVER['PHP_AUTH_PW'] );
			// phpcs:ignore WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedVariableFound -- Resets Core authentication state.
			$GLOBALS['wp_rest_auth_cookie'] = null;
			// phpcs:ignore WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedVariableFound -- Resets Core authentication state.
			$GLOBALS['wp_rest_application_password_status'] = null;
			wp_set_current_user( $prior );
		}
	}

	/**
	 * Repeats exact handler/resource selection and Ability permission ownership.
	 *
	 * @param WP_REST_Server             $server Disposable server.
	 * @param RestAuthenticationBoundary $boundary Installed boundary.
	 * @param SyntheticBearerFixtures    $fixtures Process-local fixtures.
	 * @param ProofRoutes                $routes Observable proof routes.
	 * @param int                        $user_a_id Expected administrator identity.
	 * @return array<string, bool>
	 */
	private static function runRouteMatrix( WP_REST_Server $server, RestAuthenticationBoundary $boundary, SyntheticBearerFixtures $fixtures, ProofRoutes $routes, int $user_a_id ): array {
		$validationBefore  = $boundary->validator()->validationCount();
		$permissionBefore  = $routes->permissionCount();
		$callbackBefore    = $routes->callbackCount();
		$dynamicRoute      = '/' . ProofRoutes::NAMESPACE . '/dynamic/(?P<id>[\d]+)';
		$abilityRoute      = '/' . ProofRoutes::NAMESPACE . '/ability';
		$abilityName       = 'charter-p2/process-permission-boundary';
		$categorySlug      = 'charter-p2-process-proof';
		$observations      = array();
		$dynamicChecks     = 0;
		$dynamicCallbacks  = 0;
		$abilityChecks     = 0;
		$abilityExecutions = 0;

		$dynamicHandler = static function ( string $label, string $methods, string $protectedResource ) use ( $boundary, &$observations, &$dynamicChecks, &$dynamicCallbacks ): array {
			return ProtectedRouteRegistry::assign(
				array(
					'methods'             => $methods,
					'permission_callback' => static function () use ( &$dynamicChecks ): bool {
						++$dynamicChecks;

						return true;
					},
					'callback'            => static function ( WP_REST_Request $request ) use ( $boundary, $label, &$observations, &$dynamicCallbacks ): array {
						++$dynamicCallbacks;
						$context        = $boundary->contexts()->current();
						$observations[] = array(
							'label'    => $label,
							'id'       => $request->get_url_params()['id'] ?? null,
							'method'   => $request->get_method(),
							'user_id'  => get_current_user_id(),
							'resource' => $context instanceof BearerValidationResult ? $context->resource() : null,
						);

						return array( 'selected' => $label );
					},
				),
				$label,
				$protectedResource,
				array( SyntheticBearerFixtures::GENERAL_SCOPE )
			);
		};

		$server->register_route(
			ProofRoutes::NAMESPACE,
			$dynamicRoute,
			array(
				$dynamicHandler( 'dynamic-get', 'GET', SyntheticBearerFixtures::DEFAULT_RESOURCE ),
				$dynamicHandler( 'dynamic-post', 'POST', SyntheticBearerFixtures::ISOLATED_RESOURCE ),
			)
		);

		\WP_Abilities_Registry::get_instance();
		$registerCategory = static function () use ( $categorySlug ): void {
			wp_register_ability_category(
				$categorySlug,
				array(
					'label'       => 'Charter P2 process proof',
					'description' => 'Disposable process authentication-boundary proof abilities.',
				)
			);
		};
		$registerAbility  = static function () use ( $abilityName, $categorySlug, &$abilityChecks, &$abilityExecutions ): void {
			wp_register_ability(
				$abilityName,
				array(
					'label'               => 'Check the disposable process boundary',
					'description'         => 'Returns a fixed result after WordPress permission succeeds.',
					'category'            => $categorySlug,
					'permission_callback' => static function () use ( &$abilityChecks ): bool {
						++$abilityChecks;

						return current_user_can( 'manage_options' );
					},
					'execute_callback'    => static function () use ( &$abilityExecutions ): array {
						++$abilityExecutions;

						return array( 'proved' => true );
					},
					'output_schema'       => array(
						'type'       => 'object',
						'properties' => array( 'proved' => array( 'type' => 'boolean' ) ),
						'required'   => array( 'proved' ),
					),
					'meta'                => array( 'show_in_rest' => false ),
				)
			);
		};

		add_action( 'wp_abilities_api_categories_init', $registerCategory );
		// phpcs:ignore WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedHooknameFound -- Exercises Core's required registration lifecycle.
		do_action( 'wp_abilities_api_categories_init', \WP_Ability_Categories_Registry::get_instance() );
		remove_action( 'wp_abilities_api_categories_init', $registerCategory );
		add_action( 'wp_abilities_api_init', $registerAbility );
		// phpcs:ignore WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedHooknameFound -- Exercises Core's required registration lifecycle.
		do_action( 'wp_abilities_api_init', \WP_Abilities_Registry::get_instance() );
		remove_action( 'wp_abilities_api_init', $registerAbility );

		try {
			$ability = wp_get_ability( $abilityName );
			if ( null === $ability ) {
				return self::checks( false, false, false, false, false );
			}

			$server->register_route(
				ProofRoutes::NAMESPACE,
				$abilityRoute,
				ProtectedRouteRegistry::assign(
					array(
						'methods'             => 'POST',
						'permission_callback' => static fn () => $ability->check_permissions(),
						'callback'            => static fn () => $ability->execute(),
					),
					'process-ability',
					SyntheticBearerFixtures::DEFAULT_RESOURCE,
					array( SyntheticBearerFixtures::GENERAL_SCOPE )
				)
			);

			wp_set_current_user( 0 );
			$dynamicGet = new WP_REST_Request( 'GET', str_replace( '(?P<id>[\d]+)', '41', $dynamicRoute ) );
			$fixtures->authorize( $dynamicGet, SyntheticBearerFixtures::CASE_VALID_A_DEFAULT );
			$dynamicGetResponse = $server->dispatch( $dynamicGet );

			$dynamicPost = new WP_REST_Request( 'POST', str_replace( '(?P<id>[\d]+)', '42', $dynamicRoute ) );
			$fixtures->authorize( $dynamicPost, SyntheticBearerFixtures::CASE_VALID_A_ISOLATED );
			$dynamicPostResponse = $server->dispatch( $dynamicPost );

			$dynamicHead = new WP_REST_Request( 'HEAD', str_replace( '(?P<id>[\d]+)', '43', $dynamicRoute ) );
			$fixtures->authorize( $dynamicHead, SyntheticBearerFixtures::CASE_VALID_A_DEFAULT );
			$dynamicHeadResponse = $server->dispatch( $dynamicHead );

			$wrongResource = new WP_REST_Request( 'POST', str_replace( '(?P<id>[\d]+)', '44', $dynamicRoute ) );
			$fixtures->authorize( $wrongResource, SyntheticBearerFixtures::CASE_VALID_A_DEFAULT );
			$wrongResourceResponse = $server->dispatch( $wrongResource );

			$multiGet = new WP_REST_Request( 'GET', ProofRoutes::MULTI_ROUTE );
			$fixtures->authorize( $multiGet, SyntheticBearerFixtures::CASE_VALID_A_DEFAULT );
			$multiGetResponse = $server->dispatch( $multiGet );
			$multiPost        = new WP_REST_Request( 'POST', ProofRoutes::MULTI_ROUTE );
			$fixtures->authorize( $multiPost, SyntheticBearerFixtures::CASE_VALID_A_ISOLATED );
			$multiPostResponse = $server->dispatch( $multiPost );
			$multiHead         = new WP_REST_Request( 'HEAD', ProofRoutes::MULTI_ROUTE );
			$fixtures->authorize( $multiHead, SyntheticBearerFixtures::CASE_VALID_A_DEFAULT );
			$multiHeadResponse = $server->dispatch( $multiHead );

			$options = new WP_REST_Request( 'OPTIONS', ProofRoutes::MULTI_ROUTE );
			$fixtures->authorize( $options, SyntheticBearerFixtures::CASE_UNKNOWN );
			$optionsResponse = $server->dispatch( $options );
			$wrongMethod     = new WP_REST_Request( 'DELETE', ProofRoutes::MULTI_ROUTE );
			$fixtures->authorize( $wrongMethod, SyntheticBearerFixtures::CASE_VALID_A_DEFAULT );
			$wrongMethodResponse = $server->dispatch( $wrongMethod );

			$public = new WP_REST_Request( 'GET', ProofRoutes::PUBLIC_ROUTE );
			$fixtures->authorize( $public, SyntheticBearerFixtures::CASE_UNKNOWN );
			$publicResponse = $server->dispatch( $public );
			$protected      = new WP_REST_Request( 'GET', ProofRoutes::PROTECTED_ROUTE );
			$fixtures->authorize( $protected, SyntheticBearerFixtures::CASE_VALID_A_DEFAULT );
			$protectedResponse = $server->dispatch( $protected );

			$abilityAllowed = new WP_REST_Request( 'POST', $abilityRoute );
			$fixtures->authorize( $abilityAllowed, SyntheticBearerFixtures::CASE_VALID_A_DEFAULT );
			$abilityAllowedResponse = $server->dispatch( $abilityAllowed );
			$abilityDenied          = new WP_REST_Request( 'POST', $abilityRoute );
			$fixtures->authorize( $abilityDenied, SyntheticBearerFixtures::CASE_VALID_B_DEFAULT );
			$abilityDeniedResponse = $server->dispatch( $abilityDenied );

			$identityClean = 0 === get_current_user_id();
			return self::checks(
				self::hasStatus( $dynamicGetResponse, 200 )
					&& self::hasStatus( $dynamicPostResponse, 200 )
					&& self::hasStatus( $dynamicHeadResponse, 200 )
					&& self::hasCode( $wrongResourceResponse, 401, 'invalid_token' )
					&& self::hasStatus( $multiGetResponse, 200 )
					&& self::hasStatus( $multiPostResponse, 200 )
					&& self::hasStatus( $multiHeadResponse, 200 )
					&& self::hasStatus( $optionsResponse, 200 )
					&& self::hasCode( $wrongMethodResponse, 404, 'rest_no_route' )
					&& self::hasStatus( $publicResponse, 200 )
					&& self::hasStatus( $protectedResponse, 200 )
					&& self::hasStatus( $abilityAllowedResponse, 200 )
					&& array( 'proved' => true ) === $abilityAllowedResponse->get_data()
					&& self::hasCode( $abilityDeniedResponse, 403, 'rest_forbidden' )
					&& array( 'dynamic-get', 'dynamic-post', 'dynamic-get' ) === array_column( $observations, 'label' )
					&& array( '41', '42', '43' ) === array_column( $observations, 'id' )
					&& array( 'GET', 'POST', 'HEAD' ) === array_column( $observations, 'method' )
					&& array( $user_a_id, $user_a_id, $user_a_id ) === array_column( $observations, 'user_id' )
					&& array( SyntheticBearerFixtures::DEFAULT_RESOURCE, SyntheticBearerFixtures::ISOLATED_RESOURCE, SyntheticBearerFixtures::DEFAULT_RESOURCE ) === array_column( $observations, 'resource' ),
				10 === $boundary->validator()->validationCount() - $validationBefore,
				3 === $dynamicChecks
					&& 3 === $dynamicCallbacks
					&& 3 === $abilityChecks
					&& 1 === $abilityExecutions
					&& 5 === $routes->permissionCount() - $permissionBefore
					&& 5 === $routes->callbackCount() - $callbackBefore,
				$identityClean,
				0 === $boundary->contexts()->depth()
			);
		} finally {
			wp_unregister_ability( $abilityName );
			wp_unregister_ability_category( $categorySlug );
		}
	}

	/**
	 * Repeats returned-error, nested, batch, and throwable cleanup paths.
	 *
	 * @param WP_REST_Server             $server Disposable server.
	 * @param RestAuthenticationBoundary $boundary Installed boundary.
	 * @param SyntheticBearerFixtures    $fixtures Process-local fixtures.
	 * @param ProofRoutes                $routes Observable proof routes.
	 * @param int                        $user_a_id Outer represented user.
	 * @return array<string, bool>
	 */
	private static function runCleanupMatrix( WP_REST_Server $server, RestAuthenticationBoundary $boundary, SyntheticBearerFixtures $fixtures, ProofRoutes $routes, int $user_a_id ): array {
		$routes->registerBatchRoutes( $server );
		$validationBefore  = $boundary->validator()->validationCount();
		$permissionsBefore = $routes->permissionCount();
		$callbacksBefore   = $routes->callbackCount();
		$returnedRoute     = '/' . ProofRoutes::NAMESPACE . '/returned-error';
		$nestedRoute       = '/' . ProofRoutes::NAMESPACE . '/nested';
		$throwableRoute    = '/' . ProofRoutes::NAMESPACE . '/throwable';
		$nestedState       = array();

		$server->register_route(
			ProofRoutes::NAMESPACE,
			$returnedRoute,
			ProtectedRouteRegistry::assign(
				array(
					'methods'             => 'GET',
					'permission_callback' => '__return_true',
					'callback'            => static fn (): WP_Error => new WP_Error( 'proof_returned_error', 'Returned proof error.', array( 'status' => 422 ) ),
				),
				'worker_returned_error',
				SyntheticBearerFixtures::DEFAULT_RESOURCE,
				array( SyntheticBearerFixtures::GENERAL_SCOPE )
			)
		);
		$server->register_route(
			ProofRoutes::NAMESPACE,
			$nestedRoute,
			ProtectedRouteRegistry::assign(
				array(
					'methods'             => 'GET',
					'permission_callback' => '__return_true',
					'callback'            => static function () use ( $server, $fixtures, &$nestedState ): array {
						$nestedState['before'] = get_current_user_id();
						$inner = new WP_REST_Request( 'GET', ProofRoutes::PROTECTED_ROUTE );
						$fixtures->authorize( $inner, SyntheticBearerFixtures::CASE_VALID_B_DEFAULT );
						$innerResponse         = $server->dispatch( $inner );
						$nestedState['inner']  = $innerResponse->get_status();
						$nestedState['after']  = get_current_user_id();

						return array( 'nested' => true );
					},
				),
				'worker_nested',
				SyntheticBearerFixtures::DEFAULT_RESOURCE,
				array( SyntheticBearerFixtures::GENERAL_SCOPE )
			)
		);
		$server->register_route(
			ProofRoutes::NAMESPACE,
			$throwableRoute,
			ProtectedRouteRegistry::assign(
				array(
					'methods'             => 'GET',
					'permission_callback' => '__return_true',
					'callback'            => static function (): array {
						throw new RuntimeException( 'proof_worker_throwable' );
					},
				),
				'worker_throwable',
				SyntheticBearerFixtures::DEFAULT_RESOURCE,
				array( SyntheticBearerFixtures::GENERAL_SCOPE )
			)
		);

		wp_set_current_user( 0 );
		$returnedRequest = new WP_REST_Request( 'GET', $returnedRoute );
		$fixtures->authorize( $returnedRequest, SyntheticBearerFixtures::CASE_VALID_A_DEFAULT );
		$returned = $server->dispatch( $returnedRequest );

		$nestedRequest = new WP_REST_Request( 'GET', $nestedRoute );
		$fixtures->authorize( $nestedRequest, SyntheticBearerFixtures::CASE_VALID_A_DEFAULT );
		$nested = $server->dispatch( $nestedRequest );

		$batch = new WP_REST_Request( 'POST', '/batch/v1' );
		$batch->set_body_params(
			array(
				'requests' => array(
					self::batchItem( ProofRoutes::BATCH_PROTECTED_ROUTE, $fixtures, SyntheticBearerFixtures::CASE_VALID_A_DEFAULT ),
					self::batchItem( ProofRoutes::BATCH_PUBLIC_ROUTE, $fixtures ),
					self::batchItem( ProofRoutes::BATCH_PROTECTED_ROUTE, $fixtures, SyntheticBearerFixtures::CASE_UNKNOWN ),
					self::batchItem( ProofRoutes::BATCH_PROTECTED_ROUTE, $fixtures, SyntheticBearerFixtures::CASE_VALID_B_DEFAULT ),
					self::batchItem( ProofRoutes::BATCH_PUBLIC_ROUTE, $fixtures ),
				),
			)
		);
		$batchResponse = $server->dispatch( $batch );
		$batchData     = $batchResponse->get_data();
		$batchStatuses = is_array( $batchData ) && is_array( $batchData['responses'] ?? null )
			? array_column( $batchData['responses'], 'status' )
			: array();

		$throwableRequest = new WP_REST_Request( 'GET', $throwableRoute );
		$fixtures->authorize( $throwableRequest, SyntheticBearerFixtures::CASE_VALID_A_DEFAULT );
		$throwableCaught = false;
		try {
			$boundary->dispatchExceptionSafely( $server, $throwableRequest );
		} catch ( RuntimeException $exception ) {
			$throwableCaught = 'proof_worker_throwable' === $exception->getMessage();
		}

		return self::checks(
			self::hasCode( $returned, 422, 'proof_returned_error' )
				&& self::hasStatus( $nested, 200 )
				&& array( 200, 200, 401, 200, 200 ) === $batchStatuses
				&& $throwableCaught,
			9 === $boundary->validator()->validationCount() - $validationBefore,
			9 === $routes->permissionCount() - $permissionsBefore && 5 === $routes->callbackCount() - $callbacksBefore,
			( $nestedState['before'] ?? null ) === $user_a_id
				&& 200 === ( $nestedState['inner'] ?? null )
				&& ( $nestedState['after'] ?? null ) === $user_a_id
				&& 0 === get_current_user_id(),
			0 === $boundary->contexts()->depth()
		);
	}

	/**
	 * Creates one batch item without exposing its credential.
	 *
	 * @param string                  $path Exact REST path.
	 * @param SyntheticBearerFixtures $fixtures Process-local fixtures.
	 * @param string|null             $fixtureCase Optional Bearer case.
	 * @return array<string, mixed>
	 */
	private static function batchItem( string $path, SyntheticBearerFixtures $fixtures, ?string $fixtureCase = null ): array {
		$item = array(
			'method' => 'POST',
			'path'   => $path,
		);
		if ( null !== $fixtureCase ) {
			$item['headers'] = array( 'Authorization' => $fixtures->authorizationHeader( $fixtureCase ) );
		}

		return $item;
	}

	/**
	 * Creates every forbidden Bearer transport request.
	 *
	 * @param SyntheticBearerFixtures $fixtures Process-local fixtures.
	 * @return list<WP_REST_Request>
	 */
	private static function transportRequests( SyntheticBearerFixtures $fixtures ): array {
		$requests  = array();
		$malformed = new WP_REST_Request( 'GET', ProofRoutes::PROTECTED_ROUTE );
		$malformed->set_header( 'Authorization', 'Bearer' );
		$requests[] = $malformed;
		$query      = new WP_REST_Request( 'GET', ProofRoutes::PROTECTED_ROUTE );
		$query->set_query_params( array( 'access_token' => 'alternate-proof-value' ) );
		$requests[] = $query;
		$body       = new WP_REST_Request( 'GET', ProofRoutes::PROTECTED_ROUTE );
		$body->set_body_params( array( 'access_token' => 'alternate-proof-value' ) );
		$requests[] = $body;
		$json       = new WP_REST_Request( 'GET', ProofRoutes::PROTECTED_ROUTE );
		$json->set_header( 'Content-Type', 'application/json' );
		$json->set_body( '{"access_token":"alternate-proof-value"}' );
		$requests[]      = $json;
		$alternateHeader = new WP_REST_Request( 'GET', ProofRoutes::PROTECTED_ROUTE );
		$alternateHeader->set_header( 'X-Charter-Access-Token', 'alternate-proof-value' );
		$requests[] = $alternateHeader;
		$mixed      = new WP_REST_Request( 'GET', ProofRoutes::PROTECTED_ROUTE );
		$fixtures->authorize( $mixed, SyntheticBearerFixtures::CASE_VALID_A_DEFAULT );
		$mixed->set_query_params( array( 'access_token' => 'alternate-proof-value' ) );
		$requests[] = $mixed;
		$duplicate  = new WP_REST_Request( 'GET', ProofRoutes::PROTECTED_ROUTE );
		$duplicate->add_header( 'Authorization', 'Bearer first-proof-value' );
		$duplicate->add_header( 'Authorization', 'Bearer second-proof-value' );
		$requests[] = $duplicate;

		return $requests;
	}

	/**
	 * Runs Bearer-only, mixed rejection, and public mixed input in one process.
	 *
	 * @param int $user_a_id Bearer user.
	 * @param int $user_b_id Legacy user.
	 * @return array<string, bool>
	 */
	private static function runReused( int $user_a_id, int $user_b_id ): array {
		$fixtures  = new SyntheticBearerFixtures( $user_a_id, $user_b_id );
		$boundary  = RestAuthenticationBoundary::fromFixtures( $fixtures );
		$routes    = new ProofRoutes( $boundary );
		$server    = rest_get_server();
		$prior     = get_current_user_id();
		$responses = array();

		$boundary->install();
		$routes->register( $server );

		try {
			$routeChecks     = self::runRouteMatrix( $server, $boundary, $fixtures, $routes, $user_a_id );
			$routeMatrixPass = ! in_array( false, $routeChecks, true );
			$boundary->reset();
			$routes->resetCounts();
			wp_set_current_user( 0 );
			$responses['public-first'] = $server->dispatch( new WP_REST_Request( 'GET', ProofRoutes::PUBLIC_ROUTE ) );
			$clean                     = 0 === get_current_user_id() && 0 === $boundary->contexts()->depth();

			$request = new WP_REST_Request( 'GET', ProofRoutes::PROTECTED_ROUTE );
			$fixtures->authorize( $request, SyntheticBearerFixtures::CASE_VALID_A_DEFAULT );
			$responses['bearer-a'] = $server->dispatch( $request );
			$clean                 = $clean && 0 === get_current_user_id() && 0 === $boundary->contexts()->depth();

			$_SERVER['REQUEST_METHOD']     = 'GET';
			$_SERVER['HTTP_AUTHORIZATION'] = $fixtures->authorizationHeader( SyntheticBearerFixtures::CASE_VALID_B_DEFAULT );
			ob_start();
			$server->serve_request( ProofRoutes::PROTECTED_ROUTE );
			$servedBody = ob_get_clean();
			unset( $_SERVER['HTTP_AUTHORIZATION'] );
			$responses['bearer-b-served'] = is_string( $servedBody ) ? json_decode( $servedBody, true ) : null;
			$clean                        = $clean && 0 === get_current_user_id() && 0 === $boundary->contexts()->depth();

			$request = new WP_REST_Request( 'GET', ProofRoutes::PROTECTED_ROUTE );
			$fixtures->authorize( $request, SyntheticBearerFixtures::CASE_UNKNOWN );
			$responses['invalid'] = $server->dispatch( $request );

			$responses['missing'] = $server->dispatch( new WP_REST_Request( 'GET', ProofRoutes::PROTECTED_ROUTE ) );

			$request = new WP_REST_Request( 'GET', ProofRoutes::PROTECTED_ROUTE );
			$fixtures->authorize( $request, SyntheticBearerFixtures::CASE_INSUFFICIENT_SCOPE );
			$responses['scope'] = $server->dispatch( $request );

			$request = new WP_REST_Request( 'GET', ProofRoutes::DENIED_ROUTE );
			$fixtures->authorize( $request, SyntheticBearerFixtures::CASE_VALID_A_DEFAULT );
			$responses['denied'] = $server->dispatch( $request );

			$reusedErrorPass = true;
			foreach ( array(
				SyntheticBearerFixtures::CASE_EXPIRED,
				SyntheticBearerFixtures::CASE_REVOKED,
				SyntheticBearerFixtures::CASE_WRONG_ISSUER,
				SyntheticBearerFixtures::CASE_WRONG_RESOURCE,
				SyntheticBearerFixtures::CASE_WRONG_CLIENT,
				SyntheticBearerFixtures::CASE_WRONG_USER,
				SyntheticBearerFixtures::CASE_WRONG_GRANT,
				SyntheticBearerFixtures::CASE_POLICY_DENIED,
				SyntheticBearerFixtures::CASE_MALFORMED,
			) as $fixtureCase ) {
				$invalidRequest = new WP_REST_Request( 'GET', ProofRoutes::PROTECTED_ROUTE );
				$fixtures->authorize( $invalidRequest, $fixtureCase );
				$casePassed      = self::hasCode( $server->dispatch( $invalidRequest ), 401, 'invalid_token' );
				$reusedErrorPass = $casePassed && $reusedErrorPass;
			}
			foreach ( self::transportRequests( $fixtures ) as $transportRequest ) {
				$casePassed      = self::hasCode( $server->dispatch( $transportRequest ), 400, 'invalid_request' );
				$reusedErrorPass = $casePassed && $reusedErrorPass;
			}

			$cleanupChecks = self::runCleanupMatrix( $server, $boundary, $fixtures, $routes, $user_a_id );

			wp_set_current_user( $user_b_id );
			// phpcs:ignore WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedVariableFound -- Exercises Core cookie authentication.
			$GLOBALS['wp_rest_auth_cookie'] = true;
			$_SERVER['HTTP_X_WP_NONCE']     = wp_create_nonce( 'wp_rest' );
			$cookieAuthenticated            = true === $server->check_authentication();
			$responses['legacy-cookie']     = $server->dispatch( new WP_REST_Request( 'GET', ProofRoutes::PROTECTED_ROUTE ) );
			unset( $_SERVER['HTTP_X_WP_NONCE'] );
			// phpcs:ignore WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedVariableFound -- Resets Core cookie authentication.
			$GLOBALS['wp_rest_auth_cookie'] = null;
			wp_set_current_user( 0 );

			$application             = WP_Application_Passwords::create_new_application_password( $user_b_id, array( 'name' => 'Charter P2 reused proof' ) );
			$appAuthenticated        = false;
			$responses['legacy-app'] = null;
			if ( is_array( $application ) && is_string( $application[0] ?? null ) ) {
				add_filter( 'wp_is_application_passwords_available', '__return_true' );
				add_filter( 'application_password_is_api_request', '__return_true' );
				try {
					$user = get_userdata( $user_b_id );
					if ( false !== $user ) {
						$_SERVER['PHP_AUTH_USER'] = $user->user_login;
						$_SERVER['PHP_AUTH_PW']   = $application[0];
						$validatedUserId          = wp_validate_application_password( false );
						wp_set_current_user( is_int( $validatedUserId ) ? $validatedUserId : 0 );
						$appAuthenticated        = true === $server->check_authentication();
						$responses['legacy-app'] = $server->dispatch( new WP_REST_Request( 'GET', ProofRoutes::PROTECTED_ROUTE ) );
					}
				} finally {
					remove_filter( 'wp_is_application_passwords_available', '__return_true' );
					remove_filter( 'application_password_is_api_request', '__return_true' );
					unset( $_SERVER['PHP_AUTH_USER'], $_SERVER['PHP_AUTH_PW'] );
					// phpcs:ignore WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedVariableFound -- Resets Core Application Password status.
					$GLOBALS['wp_rest_application_password_status'] = null;
					WP_Application_Passwords::delete_all_application_passwords( $user_b_id );
				}
			}

			wp_set_current_user( $user_b_id );
			// phpcs:ignore WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedVariableFound -- Exercises Core missing-nonce behavior.
			$GLOBALS['wp_rest_auth_cookie'] = true;
			$missingNonceAuthenticated      = true === $server->check_authentication() && 0 === get_current_user_id();
			$request                        = new WP_REST_Request( 'GET', ProofRoutes::PROTECTED_ROUTE );
			$fixtures->authorize( $request, SyntheticBearerFixtures::CASE_VALID_A_DEFAULT );
			$responses['missing-nonce-bearer'] = $server->dispatch( $request );

			wp_set_current_user( $user_b_id );
			$request = new WP_REST_Request( 'GET', ProofRoutes::PROTECTED_ROUTE );
			$fixtures->authorize( $request, SyntheticBearerFixtures::CASE_VALID_A_DEFAULT );
			$responses['mixed'] = $server->dispatch( $request );

			$request = new WP_REST_Request( 'GET', ProofRoutes::PUBLIC_ROUTE );
			$fixtures->authorize( $request, SyntheticBearerFixtures::CASE_VALID_A_DEFAULT );
			$responses['public-last'] = $server->dispatch( $request );
			$clean                    = $clean && get_current_user_id() === $user_b_id && 0 === $boundary->contexts()->depth();

			return self::checks(
				$routeMatrixPass
					&& self::hasStatus( $responses['public-first'], 200 )
					&& self::hasStatus( $responses['bearer-a'], 200 )
					&& is_array( $responses['bearer-b-served'] )
					&& 'protected' === ( $responses['bearer-b-served']['route'] ?? null )
					&& self::hasCode( $responses['invalid'], 401, 'invalid_token' )
					&& self::hasCode( $responses['missing'], 401, 'rest_not_logged_in' )
					&& self::hasCode( $responses['scope'], 403, 'insufficient_scope' )
					&& self::hasCode( $responses['denied'], 403, 'rest_forbidden' )
					&& $reusedErrorPass
					&& ! in_array( false, $cleanupChecks, true )
					&& $cookieAuthenticated
					&& self::hasStatus( $responses['legacy-cookie'], 200 )
					&& $appAuthenticated
					&& self::hasStatus( $responses['legacy-app'], 200 )
					&& $missingNonceAuthenticated
					&& self::hasStatus( $responses['missing-nonce-bearer'], 200 )
					&& self::isMixedRejection( $responses['mixed'] )
					&& self::hasStatus( $responses['public-last'], 200 ),
				32 === $boundary->validator()->validationCount(),
				18 === $routes->permissionCount() && 12 === $routes->callbackCount(),
				$clean,
				0 === $boundary->contexts()->depth()
			);
		} finally {
			$boundary->remove();
			unset( $_SERVER['HTTP_X_WP_NONCE'], $_SERVER['HTTP_AUTHORIZATION'], $_SERVER['PHP_AUTH_USER'], $_SERVER['PHP_AUTH_PW'] );
			// phpcs:ignore WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedVariableFound -- Resets Core authentication state.
			$GLOBALS['wp_rest_auth_cookie'] = null;
			// phpcs:ignore WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedVariableFound -- Resets Core authentication state.
			$GLOBALS['wp_rest_application_password_status'] = null;
			wp_set_current_user( $prior );
		}
	}

	/**
	 * Checks the exact generic mixed-authentication response.
	 *
	 * @param mixed $response REST response.
	 */
	private static function isMixedRejection( mixed $response ): bool {
		if ( ! $response instanceof WP_REST_Response || 400 !== $response->get_status() ) {
			return false;
		}

		$data      = $response->get_data();
		$challenge = $response->get_headers()['WWW-Authenticate'] ?? null;

		return is_array( $data )
			&& 'invalid_request' === ( $data['code'] ?? null )
			&& is_string( $challenge )
			&& ChallengeParser::isExact(
				$challenge,
				array(
					'error'             => 'invalid_request',
					'resource_metadata' => self::RESOURCE_METADATA,
				)
			);
	}

	/**
	 * Checks an exact REST response status and code.
	 *
	 * @param mixed  $response Candidate response.
	 * @param int    $status Expected status.
	 * @param string $code Expected REST code.
	 */
	private static function hasCode( mixed $response, int $status, string $code ): bool {
		if ( ! $response instanceof WP_REST_Response || $status !== $response->get_status() ) {
			return false;
		}

		$data = $response->get_data();

		return is_array( $data ) && ( $data['code'] ?? null ) === $code;
	}

	/**
	 * Checks an exact REST response status.
	 *
	 * @param mixed $response Candidate response.
	 * @param int   $status Expected status.
	 */
	private static function hasStatus( mixed $response, int $status ): bool {
		return $response instanceof WP_REST_Response && $status === $response->get_status();
	}

	/**
	 * Returns the fixed worker check map.
	 *
	 * @param bool $response   Response contract passed.
	 * @param bool $validation Validator count passed.
	 * @param bool $callbacks  Callback counts passed.
	 * @param bool $identity   Identity contract passed.
	 * @param bool $context    Context cleanup passed.
	 * @return array<string, bool>
	 */
	private static function checks( bool $response, bool $validation, bool $callbacks, bool $identity, bool $context ): array {
		return array(
			'wordpress_6_9'          => FixtureContract::isSupportedWordPressVersion( $GLOBALS['wp_version'] ?? null ),
			'expected_response'      => $response,
			'validation_count_exact' => $validation,
			'callbacks_exact'        => $callbacks,
			'identity_unchanged'     => $identity,
			'context_depth_zero'     => $context,
		);
	}
}

$charter_p2_worker_args   = isset( $args ) && is_array( $args ) ? $args : array();
$charter_p2_worker_mode   = is_string( $charter_p2_worker_args[0] ?? null ) ? $charter_p2_worker_args[0] : '';
$charter_p2_worker_user_a = filter_var( $charter_p2_worker_args[1] ?? null, FILTER_VALIDATE_INT );
$charter_p2_worker_user_b = filter_var( $charter_p2_worker_args[2] ?? null, FILTER_VALIDATE_INT );
$charter_p2_worker_checks = array();

// phpcs:ignore WordPress.PHP.IniSet.display_errors_Disallowed -- The standalone proof worker must suppress unexpected diagnostics.
ini_set( 'display_errors', '0' );
// phpcs:ignore WordPress.PHP.IniSet.log_errors_Disallowed -- The standalone proof worker must not persist failure detail.
ini_set( 'log_errors', '0' );
ob_start();

try {
	if (
		! in_array( $charter_p2_worker_mode, WorkerContract::MODES, true )
		|| ! is_int( $charter_p2_worker_user_a )
		|| ! is_int( $charter_p2_worker_user_b )
		|| 1 > $charter_p2_worker_user_a
		|| 1 > $charter_p2_worker_user_b
	) {
		// phpcs:ignore WordPress.Security.EscapeOutput.ExceptionNotEscaped -- The fixed outer catch suppresses this diagnostic.
		throw new RuntimeException( 'Invalid worker invocation.' );
	}

	$charter_p2_worker_checks = ProcessWorkerScenario::run(
		$charter_p2_worker_mode,
		$charter_p2_worker_user_a,
		$charter_p2_worker_user_b
	);
} catch ( Throwable ) {
	$charter_p2_worker_checks = array();
}

while ( 0 < ob_get_level() ) {
	ob_end_clean();
}

$charter_p2_worker_result = WorkerContract::result( $charter_p2_worker_mode, $charter_p2_worker_checks );
// phpcs:ignore WordPress.WP.AlternativeFunctions.json_encode_json_encode -- Emits the private fixed boolean-only worker contract.
echo json_encode( $charter_p2_worker_result, JSON_THROW_ON_ERROR );
echo "\n";
exit( $charter_p2_worker_result['passed'] ? 0 : 1 );
