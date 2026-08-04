<?php
/**
 * WordPress REST authentication-boundary behavior tests.
 *
 * @package GalatanOvidiu\Charter
 */

declare(strict_types=1);

namespace GalatanOvidiu\Charter\Tests\Integration\RestAuthenticationBoundary;

use GalatanOvidiu\Charter\Tests\Prototype\RestAuthenticationBoundary\ProtectedRouteAssignment;
use GalatanOvidiu\Charter\Tests\Prototype\RestAuthenticationBoundary\BearerValidationResult;
use GalatanOvidiu\Charter\Tests\Prototype\RestAuthenticationBoundary\SyntheticBearerFixtures;
use InvalidArgumentException;
use WP_Application_Passwords;
use WP_Error;
use WP_REST_Request;

/**
 * Proves matched-handler, response, and WordPress-permission ownership.
 *
 * @since 0.1.0
 */
final class RestAuthenticationBoundaryBehaviorTest extends RestAuthenticationBoundaryTestCase {

	/**
	 * Proves resource assignments reject every individually forbidden URI component.
	 */
	public function testProtectedResourceAssignmentRejectsAmbiguousUriComponents(): void {
		$resources = array(
			'https://user@charter.example.test',
			'https://user:pass@charter.example.test',
			'https://charter.example.test?query=1',
			'https://charter.example.test#fragment',
		);

		foreach ( $resources as $resource ) {
			try {
				new ProtectedRouteAssignment( 'invalid', $resource, array( SyntheticBearerFixtures::GENERAL_SCOPE ) );
				self::fail( 'Expected the ambiguous protected-resource URI to be rejected.' );
			} catch ( InvalidArgumentException $exception ) {
				self::assertSame( 'rest_auth_boundary_assignment_invalid', $exception->getMessage() );
			}
		}
	}

	/**
	 * Proves exact default/isolated/dynamic/method selection and inert bypasses.
	 */
	public function testOnlyTheExactCoreSelectedHandlerActivatesItsAssignedResource(): void {
		$observations = array();
		$callback     = function ( WP_REST_Request $request ) use ( &$observations ): array {
			$context        = $this->boundary->contexts()->current();
			$observations[] = array(
				'method'   => $request->get_method(),
				'id'       => $request->get_url_params()['id'] ?? null,
				'user_id'  => get_current_user_id(),
				'resource' => $context instanceof BearerValidationResult ? $context->resource() : null,
			);

			return array( 'selected' => true );
		};

		$this->register(
			'/records/(?P<id>[\d]+)',
			array(
				$this->assigned(
					array(
						'methods'             => 'GET',
						'permission_callback' => '__return_true',
						'callback'            => $callback,
					),
					'dynamic_get'
				),
				$this->assigned(
					array(
						'methods'             => 'POST',
						'permission_callback' => '__return_true',
						'callback'            => $callback,
					),
					'dynamic_post',
					self::ISOLATED_RESOURCE
				),
			)
		);
		$this->register(
			'/records/public',
			array(
				array(
					'methods'             => 'GET',
					'permission_callback' => '__return_true',
					'callback'            => static fn (): array => array( 'public' => true ),
				),
			)
		);

		$cases = array(
			array( 'GET', '/records/41', SyntheticBearerFixtures::CASE_VALID_A_DEFAULT, self::DEFAULT_RESOURCE ),
			array( 'POST', '/records/42', SyntheticBearerFixtures::CASE_VALID_A_ISOLATED, self::ISOLATED_RESOURCE ),
			array( 'HEAD', '/records/43', SyntheticBearerFixtures::CASE_VALID_A_DEFAULT, self::DEFAULT_RESOURCE ),
		);

		foreach ( $cases as $case ) {
			$response = $this->dispatch( $this->authorizedRequest( $case[0], $case[1], $case[2] ) );

			self::assertSame( 200, $response->get_status() );
			self::assertSame( $case[3], end( $observations )['resource'] );
			self::assertSame( $this->userAId, end( $observations )['user_id'] );
			$this->assertProofStateClean();
		}

		$wrongResource = $this->dispatch(
			$this->authorizedRequest( 'POST', '/records/44', SyntheticBearerFixtures::CASE_VALID_A_DEFAULT )
		);
		self::assertSame( 401, $wrongResource->get_status() );
		self::assertSame( 'invalid_token', $wrongResource->get_data()['code'] );

		$public = $this->dispatch(
			$this->authorizedRequest( 'GET', '/records/public', SyntheticBearerFixtures::CASE_UNKNOWN )
		);
		self::assertSame( 200, $public->get_status() );
		self::assertSame( array( 'public' => true ), $public->get_data() );

		$validationsBeforeBypasses = $this->boundary->validator()->validationCount();
		$options                   = $this->dispatch(
			$this->authorizedRequest( 'OPTIONS', '/records/45', SyntheticBearerFixtures::CASE_VALID_A_DEFAULT )
		);
		$wrongMethod               = $this->dispatch(
			$this->authorizedRequest( 'DELETE', '/records/46', SyntheticBearerFixtures::CASE_VALID_A_DEFAULT )
		);

		self::assertSame( 200, $options->get_status() );
		self::assertSame( 404, $wrongMethod->get_status() );
		self::assertSame( 'rest_no_route', $wrongMethod->get_data()['code'] );
		self::assertSame( $validationsBeforeBypasses, $this->boundary->validator()->validationCount() );
		$this->assertProofStateClean();
	}

	/**
	 * Proves unassigned selected handlers and OPTIONS retain Core Allow behavior.
	 */
	public function testHybridRouteUsesOnlyTheCoreSelectedHandlerForBoundaryActivation(): void {
		$permissionObservations = array();
		$public                 = array(
			'methods'             => 'GET',
			'permission_callback' => static function () use ( &$permissionObservations ): bool {
				$permissionObservations[] = array(
					'handler' => 'public',
					'user_id' => get_current_user_id(),
				);

				return true;
			},
			'callback'            => static fn (): array => array( 'public' => true ),
		);
		$protected              = $this->assigned(
			array(
				'methods'             => 'POST',
				'permission_callback' => static function () use ( &$permissionObservations ): bool {
					$permissionObservations[] = array(
						'handler' => 'protected',
						'user_id' => get_current_user_id(),
					);

					return true;
				},
				'callback'            => static fn (): array => array( 'protected' => true ),
			),
			'hybrid_post',
			self::ISOLATED_RESOURCE
		);
		$this->register( '/hybrid', array( $public, $protected ) );

		$request  = $this->authorizedRequest( 'GET', '/hybrid', SyntheticBearerFixtures::CASE_UNKNOWN );
		$response = $this->dispatch( $request );
		// phpcs:ignore WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedHooknameFound -- Exercises the installed exact-handler Allow pass.
		$response = apply_filters( 'rest_post_dispatch', $response, $this->server, $request );

		self::assertSame( 200, $response->get_status() );
		self::assertSame( array( 'public' => true ), $response->get_data() );
		self::assertSame( 'GET, POST', $response->get_headers()['Allow'] );
		self::assertSame( array( 'public', 'public', 'protected' ), array_column( $permissionObservations, 'handler' ) );
		self::assertSame( array( 0, 0, 0 ), array_column( $permissionObservations, 'user_id' ) );
		self::assertSame( 0, $this->boundary->validator()->validationCount() );
		$this->assertProofStateClean();

		$options         = $this->authorizedRequest( 'OPTIONS', '/hybrid', SyntheticBearerFixtures::CASE_UNKNOWN );
		$optionsResponse = $this->dispatch( $options );
		// phpcs:ignore WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedHooknameFound -- Exercises Core OPTIONS post-dispatch behavior.
		$optionsResponse = apply_filters( 'rest_post_dispatch', $optionsResponse, $this->server, $options );
		self::assertSame( 200, $optionsResponse->get_status() );
		self::assertSame( 'GET, POST', $optionsResponse->get_headers()['Allow'] );
		self::assertSame( 0, $this->boundary->validator()->validationCount() );
		$this->assertProofStateClean();

		$permissionObservations = array();
		$post                   = $this->authorizedRequest( 'POST', '/hybrid', SyntheticBearerFixtures::CASE_VALID_A_ISOLATED );
		$postResponse           = $this->dispatch( $post );
		// phpcs:ignore WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedHooknameFound -- Exercises the installed exact-handler Allow pass.
		$postResponse = apply_filters( 'rest_post_dispatch', $postResponse, $this->server, $post );

		self::assertSame( 200, $postResponse->get_status() );
		self::assertSame( 'GET, POST', $postResponse->get_headers()['Allow'] );
		self::assertSame( array( 'protected', 'public', 'protected' ), array_column( $permissionObservations, 'handler' ) );
		self::assertSame( array( $this->userAId, 0, $this->userAId ), array_column( $permissionObservations, 'user_id' ) );
		self::assertSame( 2, $this->boundary->validator()->validationCount() );
		$this->assertProofStateClean();

		$permissionObservations = array();
		wp_set_current_user( $this->userBId );
		$mixed         = $this->authorizedRequest( 'POST', '/hybrid', SyntheticBearerFixtures::CASE_VALID_A_ISOLATED );
		$mixedResponse = $this->dispatch( $mixed );
		// phpcs:ignore WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedHooknameFound -- Proves rejected mixed authentication suppresses every Allow permission callback.
		$mixedResponse = apply_filters( 'rest_post_dispatch', $mixedResponse, $this->server, $mixed );

		self::assertSame( 400, $mixedResponse->get_status() );
		self::assertSame( 'invalid_request', $mixedResponse->get_data()['code'] );
		self::assertArrayNotHasKey( 'Allow', $mixedResponse->get_headers() );
		self::assertSame( array(), $permissionObservations );
		self::assertSame( 2, $this->boundary->validator()->validationCount() );
		self::assertSame( $this->userBId, get_current_user_id() );
		self::assertSame( 0, $this->boundary->contexts()->depth() );
	}

	/**
	 * Proves the exact missing, invalid-state, and insufficient-scope contracts.
	 */
	public function testBearerAuthenticationResponsesCoverEverySemanticState(): void {
		$permissionCalls = 0;
		$callbackCalls   = 0;
		$this->registerCountingProtectedRoute( $permissionCalls, $callbackCalls );

		$missing = $this->dispatch( $this->request( 'GET', '/protected' ) );
		self::assertSame( 401, $missing->get_status() );
		self::assertSame( 'rest_not_logged_in', $missing->get_data()['code'] );
		self::assertSame(
			array(
				'resource_metadata' => self::DEFAULT_METADATA,
				'scope'             => SyntheticBearerFixtures::GENERAL_SCOPE,
			),
			self::parseBearerChallenge( $missing )
		);

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
			$response = $this->dispatch(
				$this->authorizedRequest( 'GET', '/protected', $fixtureCase )
			);

			self::assertSame( 401, $response->get_status() );
			self::assertSame( 'invalid_token', $response->get_data()['code'] );
			self::assertSame(
				array(
					'error'             => 'invalid_token',
					'resource_metadata' => self::DEFAULT_METADATA,
				),
				self::parseBearerChallenge( $response )
			);
			self::assertSame( array( 'code', 'message', 'data' ), array_keys( $response->get_data() ) );
			$this->assertProofStateClean();
		}

		$insufficient = $this->dispatch(
			$this->authorizedRequest( 'GET', '/protected', SyntheticBearerFixtures::CASE_INSUFFICIENT_SCOPE )
		);
		self::assertSame( 403, $insufficient->get_status() );
		self::assertSame( 'insufficient_scope', $insufficient->get_data()['code'] );
		self::assertSame(
			array(
				'error'             => 'insufficient_scope',
				'resource_metadata' => self::DEFAULT_METADATA,
				'scope'             => SyntheticBearerFixtures::GENERAL_SCOPE,
			),
			self::parseBearerChallenge( $insufficient )
		);
		self::assertSame( 0, $permissionCalls );
		self::assertSame( 0, $callbackCalls );
		$this->assertProofStateClean();
	}

	/**
	 * Proves every forbidden bearer transport fails before route permission.
	 */
	public function testMalformedAndAlternateBearerTransportsReturnGenericInvalidRequest(): void {
		$permissionCalls = 0;
		$callbackCalls   = 0;
		$this->registerCountingProtectedRoute( $permissionCalls, $callbackCalls );

		$requests        = array();
		$malformedHeader = $this->request( 'GET', '/protected' );
		$malformedHeader->set_header( 'Authorization', 'Bearer' );
		$requests[] = $malformedHeader;

		$query = $this->request( 'GET', '/protected' );
		$query->set_query_params( array( 'access_token' => 'alternate-proof-value' ) );
		$requests[] = $query;

		$body = $this->request( 'GET', '/protected' );
		$body->set_body_params( array( 'access_token' => 'alternate-proof-value' ) );
		$requests[] = $body;

		$json = $this->request( 'GET', '/protected' );
		$json->set_header( 'Content-Type', 'application/json' );
		$json->set_body( '{"access_token":"alternate-proof-value"}' );
		$requests[] = $json;

		$alternateHeader = $this->request( 'GET', '/protected' );
		$alternateHeader->set_header( 'X-Charter-Access-Token', 'alternate-proof-value' );
		$requests[] = $alternateHeader;

		$mixed = $this->authorizedRequest( 'GET', '/protected', SyntheticBearerFixtures::CASE_VALID_A_DEFAULT );
		$mixed->set_query_params( array( 'access_token' => 'alternate-proof-value' ) );
		$requests[] = $mixed;

		$duplicate = $this->request( 'GET', '/protected' );
		$duplicate->add_header( 'Authorization', 'Bearer first-proof-value' );
		$duplicate->add_header( 'Authorization', 'Bearer second-proof-value' );
		$requests[] = $duplicate;

		foreach ( $requests as $request ) {
			$response = $this->dispatch( $request );

			self::assertSame( 400, $response->get_status() );
			self::assertSame( 'invalid_request', $response->get_data()['code'] );
			self::assertSame(
				array(
					'error'             => 'invalid_request',
					'resource_metadata' => self::DEFAULT_METADATA,
				),
				self::parseBearerChallenge( $response )
			);
			$this->assertProofStateClean();
		}

		self::assertSame( 0, $permissionCalls );
		self::assertSame( 0, $callbackCalls );
	}

	/**
	 * Proves valid Bearer context precedes both existing route callbacks.
	 */
	public function testValidBearerEstablishesExactUserAndContextWithoutReplacingRoutePermission(): void {
		$observations = array();
		$this->register(
			'/protected',
			array(
				$this->assigned(
					array(
						'methods'             => 'GET',
						'permission_callback' => function () use ( &$observations ): bool {
							$observations['permission'] = $this->currentObservation();

							return true;
						},
						'callback'            => function () use ( &$observations ): array {
							$observations['callback'] = $this->currentObservation();

							return array( 'allowed' => true );
						},
					),
					'default_get'
				),
			)
		);

		$response = $this->dispatch(
			$this->authorizedRequest( 'GET', '/protected', SyntheticBearerFixtures::CASE_VALID_A_DEFAULT )
		);

		$expected = array(
			'user_id'  => $this->userAId,
			'resource' => self::DEFAULT_RESOURCE,
			'scopes'   => array( SyntheticBearerFixtures::GENERAL_SCOPE ),
			'depth'    => 1,
		);
		self::assertSame( 200, $response->get_status() );
		self::assertSame( $expected, $observations['permission'] );
		self::assertSame( $expected, $observations['callback'] );
		$this->assertProofStateClean();
	}

	/**
	 * Proves false/null/custom WordPress permission denial is never OAuth-rewritten.
	 */
	public function testWordPressPermissionDenialsRemainTheFinalIndependentGate(): void {
		$callbackCalls = 0;
		$cases         = array(
			array( 'false', false, 'rest_forbidden', 403 ),
			array( 'null', null, 'rest_forbidden', 403 ),
			array( 'error', new WP_Error( 'proof_object_forbidden', 'Object denied.', array( 'status' => 409 ) ), 'proof_object_forbidden', 409 ),
		);

		foreach ( $cases as $case ) {
			$permissionUser = 0;
			$this->register(
				'/denied-' . $case[0],
				array(
					$this->assigned(
						array(
							'methods'             => 'GET',
							'permission_callback' => function () use ( &$permissionUser, $case ) {
								$permissionUser = get_current_user_id();

								return $case[1];
							},
							'callback'            => static function () use ( &$callbackCalls ): array {
								++$callbackCalls;

								return array( 'unexpected' => true );
							},
						),
						'denied_' . $case[0]
					),
				)
			);

			$response = $this->dispatch(
				$this->authorizedRequest( 'GET', '/denied-' . $case[0], SyntheticBearerFixtures::CASE_VALID_A_DEFAULT )
			);

			self::assertSame( $case[3], $response->get_status() );
			self::assertSame( $case[2], $response->get_data()['code'] );
			self::assertSame( $this->userAId, $permissionUser );
			self::assertArrayNotHasKey( 'WWW-Authenticate', $response->get_headers() );
			$this->assertProofStateClean();
		}

		self::assertSame( 0, $callbackCalls );
	}

	/**
	 * Proves a disposable Ability permission callback remains authoritative.
	 */
	public function testDisposableAbilityPermissionCannotBeBypassedByValidBearer(): void {
		$abilityName       = 'charter-p2/permission-boundary';
		$categorySlug      = 'charter-p2-proof';
		$abilityChecks     = 0;
		$abilityExecutions = 0;

		\WP_Abilities_Registry::get_instance();
		$registerCategory = static function () use ( $categorySlug ): void {
			wp_register_ability_category(
				$categorySlug,
				array(
					'label'       => 'Charter P2 proof',
					'description' => 'Disposable authentication-boundary proof abilities.',
				)
			);
		};
		$registerAbility  = static function () use ( $abilityName, $categorySlug, &$abilityChecks, &$abilityExecutions ): void {
			wp_register_ability(
				$abilityName,
				array(
					'label'               => 'Check the disposable boundary',
					'description'         => 'Returns a fixed proof result after WordPress permission succeeds.',
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
			self::assertNotNull( $ability );
			$this->register(
				'/ability',
				array(
					$this->assigned(
						array(
							'methods'             => 'POST',
							'permission_callback' => static fn () => $ability->check_permissions(),
							'callback'            => static fn () => $ability->execute(),
						),
						'ability_execute'
					),
				)
			);

			$allowed = $this->dispatch(
				$this->authorizedRequest( 'POST', '/ability', SyntheticBearerFixtures::CASE_VALID_A_DEFAULT )
			);
			$denied  = $this->dispatch(
				$this->authorizedRequest( 'POST', '/ability', SyntheticBearerFixtures::CASE_VALID_B_DEFAULT )
			);

			self::assertSame( 200, $allowed->get_status() );
			self::assertSame( array( 'proved' => true ), $allowed->get_data() );
			self::assertSame( 403, $denied->get_status() );
			self::assertSame( 'rest_forbidden', $denied->get_data()['code'] );
			self::assertSame( 3, $abilityChecks );
			self::assertSame( 1, $abilityExecutions );
			$this->assertProofStateClean();
		} finally {
			wp_unregister_ability( $abilityName );
			wp_unregister_ability_category( $categorySlug );
		}
	}

	/**
	 * Proves a missing cookie nonce deliberately yields to Bearer-only authentication.
	 */
	public function testMissingCookieNonceAnonymizesBeforeBearerBoundary(): void {
		$permissionUsers = array();
		$this->register(
			'/missing-nonce',
			array(
				$this->assigned(
					array(
						'methods'             => 'GET',
						'permission_callback' => static function () use ( &$permissionUsers ): bool {
							$permissionUsers[] = get_current_user_id();

							return true;
						},
						'callback'            => static fn (): array => array( 'authenticated' => true ),
					),
					'missing_nonce_get'
				),
			)
		);

		wp_set_current_user( $this->userBId );
		// phpcs:ignore WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedVariableFound -- Exercising Core cookie authentication.
		$GLOBALS['wp_rest_auth_cookie'] = true;
		unset( $_SERVER['HTTP_X_WP_NONCE'] );
		self::assertTrue( $this->server->check_authentication() );
		self::assertSame( 0, get_current_user_id() );

		$missing = $this->dispatch( $this->request( 'GET', '/missing-nonce' ) );
		self::assertSame( 401, $missing->get_status() );
		self::assertSame( 'rest_not_logged_in', $missing->get_data()['code'] );

		$bearer = $this->dispatch(
			$this->authorizedRequest( 'GET', '/missing-nonce', SyntheticBearerFixtures::CASE_VALID_A_DEFAULT )
		);
		self::assertSame( 200, $bearer->get_status() );
		self::assertSame( array( $this->userAId ), $permissionUsers );
		self::assertSame( 1, $this->boundary->validator()->validationCount() );
		$this->assertProofStateClean();
	}

	/**
	 * Proves cookie and Application Password legacy-only paths and mixed rejection.
	 */
	public function testLegacyAuthenticationIsPreservedAloneAndRejectedBeforeBearerValidationWhenMixed(): void {
		$permissionUsers = array();
		$this->register(
			'/protected',
			array(
				$this->assigned(
					array(
						'methods'             => 'GET',
						'permission_callback' => static function () use ( &$permissionUsers ): bool {
							$permissionUsers[] = get_current_user_id();

							return true;
						},
						'callback'            => static fn (): array => array( 'legacy' => true ),
					),
					'default_get'
				),
			)
		);

		$this->establishCookieAuthentication();
		$cookieOnly = $this->dispatch( $this->request( 'GET', '/protected' ) );

		self::assertSame( 200, $cookieOnly->get_status() );
		self::assertSame( array( $this->userBId ), $permissionUsers );
		self::assertSame( 0, $this->boundary->validator()->validationCount() );
		$this->assertProofStateClean( $this->userBId );

		$this->boundary->reset();
		$appPassword = WP_Application_Passwords::create_new_application_password(
			$this->userBId,
			array( 'name' => 'Charter P2 disposable behavior' )
		);
		self::assertIsArray( $appPassword );

		add_filter( 'wp_is_application_passwords_available', '__return_true' );
		add_filter( 'application_password_is_api_request', '__return_true' );

		try {
			$user = get_userdata( $this->userBId );
			self::assertNotFalse( $user );
			$_SERVER['PHP_AUTH_USER'] = $user->user_login;
			$_SERVER['PHP_AUTH_PW']   = $appPassword[0];

			$validatedUserId = wp_validate_application_password( false );
			self::assertSame( $this->userBId, $validatedUserId );
			wp_set_current_user( $validatedUserId );
			self::assertTrue( $this->server->check_authentication() );

			$appOnly = $this->dispatch( $this->request( 'GET', '/protected' ) );
			self::assertSame( 200, $appOnly->get_status() );
			self::assertSame( 0, $this->boundary->validator()->validationCount() );

			$mixed = $this->dispatch(
				$this->authorizedRequest( 'GET', '/protected', SyntheticBearerFixtures::CASE_UNKNOWN )
			);
			self::assertSame( 400, $mixed->get_status() );
			self::assertSame( 'invalid_request', $mixed->get_data()['code'] );
			self::assertSame(
				'Use either WordPress authentication or Bearer authentication, not both.',
				$mixed->get_data()['message']
			);
			self::assertSame( 0, $this->boundary->validator()->validationCount() );
			self::assertSame( 2, count( $permissionUsers ) );
			$this->assertProofStateClean( $this->userBId );
		} finally {
			remove_filter( 'wp_is_application_passwords_available', '__return_true' );
			remove_filter( 'application_password_is_api_request', '__return_true' );
		}
	}

	/**
	 * Registers the default protected route with counters.
	 *
	 * @param int $permissionCalls Permission calls.
	 * @param int $callbackCalls   Main callback calls.
	 */
	private function registerCountingProtectedRoute( int &$permissionCalls, int &$callbackCalls ): void {
		$this->register(
			'/protected',
			array(
				$this->assigned(
					array(
						'methods'             => 'GET',
						'permission_callback' => static function () use ( &$permissionCalls ): bool {
							++$permissionCalls;

							return true;
						},
						'callback'            => static function () use ( &$callbackCalls ): array {
							++$callbackCalls;

							return array( 'protected' => true );
						},
					),
					'default_get'
				),
			)
		);
	}

	/**
	 * Captures the currently represented public proof state.
	 *
	 * @return array{user_id: int, resource: string|null, scopes: list<string>, depth: int}
	 */
	private function currentObservation(): array {
		$context = $this->boundary->contexts()->current();

		return array(
			'user_id'  => get_current_user_id(),
			'resource' => $context instanceof BearerValidationResult ? $context->resource() : null,
			'scopes'   => $context instanceof BearerValidationResult ? $context->scopes() : array(),
			'depth'    => $this->boundary->contexts()->depth(),
		);
	}

	/**
	 * Establishes successful Core cookie/nonce authentication for user B.
	 */
	private function establishCookieAuthentication(): void {
		wp_set_current_user( $this->userBId );
		// phpcs:ignore WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedVariableFound -- Exercising Core cookie authentication.
		$GLOBALS['wp_rest_auth_cookie'] = true;
		$_SERVER['HTTP_X_WP_NONCE']     = wp_create_nonce( 'wp_rest' );

		self::assertTrue( $this->server->check_authentication() );
	}
}
