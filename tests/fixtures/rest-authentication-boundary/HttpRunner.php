<?php
/**
 * Real-HTTP matrix runner for the disposable Slice 0 P2 proof.
 *
 * Run through `wp eval-file` inside the parent-owned wp-env CLI container. All
 * authentication material remains in this process and cURL's in-memory state.
 *
 * @package GalatanOvidiu\Charter
 */

declare(strict_types=1);

namespace GalatanOvidiu\Charter\Tests\Fixtures\RestAuthenticationBoundary;

use GalatanOvidiu\Charter\Tests\Prototype\RestAuthenticationBoundary\SyntheticBearerFixtures;
use RuntimeException;
use Throwable;
use WP_Application_Passwords;

require_once dirname( __DIR__, 3 ) . '/vendor/autoload.php';
require_once __DIR__ . '/FixtureContract.php';
require_once __DIR__ . '/OwnedProofUsers.php';
require_once __DIR__ . '/ChallengeParser.php';

/**
 * Executes and validates final WordPress REST responses over real HTTP.
 */
final class HttpRunner {

	private const REQUEST_TIMEOUT_SECONDS = 10;

	private const MAX_RESPONSE_BYTES = 1048576;

	private const RESOURCE_METADATA = 'https://charter.example.test/.well-known/oauth-protected-resource';

	private const ENDPOINT = 'http://wordpress/wp-content/plugins/charter/tests/fixtures/rest-authentication-boundary/HttpWorker.php';

	/**
	 * Runs the complete HTTP matrix.
	 *
	 * @param string $run_id Exact disposable run identifier.
	 * @return array<string, mixed>
	 * @throws RuntimeException When disposable setup is unavailable.
	 */
	public static function run( string $run_id ): array {
		$users       = new OwnedProofUsers( $run_id );
		$credentials = array();
		$responses   = array();
		$checks      = array();
		$cleanup     = false;
		$prior_user  = get_current_user_id();

		try {
			$user_ids = $users->create();
			$user_b   = get_userdata( $user_ids['user_b_id'] );
			if ( false === $user_b ) {
				throw new RuntimeException( 'Disposable proof user was unavailable.' );
			}

			wp_set_current_user( $user_ids['user_b_id'] );
			$cookie                      = wp_generate_auth_cookie( $user_ids['user_b_id'], time() + 600, 'logged_in' );
			$_COOKIE[ LOGGED_IN_COOKIE ] = $cookie;
			$nonce                       = wp_create_nonce( 'wp_rest' );
			unset( $_COOKIE[ LOGGED_IN_COOKIE ] );
			wp_set_current_user( $prior_user );

			$application = WP_Application_Passwords::create_new_application_password(
				$user_ids['user_b_id'],
				array(
					'name'   => 'charter-p2-' . $run_id,
					'app_id' => wp_generate_uuid4(),
				)
			);

			if ( is_wp_error( $application ) || ! is_string( $application[0] ?? null ) ) {
				throw new RuntimeException( 'Disposable Application Password was unavailable.' );
			}

			$app_password    = $application[0];
			$bearer          = bin2hex( random_bytes( 32 ) );
			$invalid_nonce   = bin2hex( random_bytes( 24 ) );
			$invalid_app     = bin2hex( random_bytes( 32 ) );
			$alternate_token = bin2hex( random_bytes( 32 ) );
			$cookie_header   = LOGGED_IN_COOKIE . '=' . $cookie;
			// phpcs:ignore WordPress.PHP.DiscouragedPHPFunctions.obfuscation_base64_encode -- Mirrors private HTTP Basic wire encoding for leak scanning.
			$basic_header = base64_encode( $user_b->user_login . ':' . $app_password );
			// phpcs:ignore WordPress.PHP.DiscouragedPHPFunctions.obfuscation_base64_encode -- Mirrors private HTTP Basic wire encoding for leak scanning.
			$invalid_basic_header = base64_encode( $user_b->user_login . ':' . $invalid_app );
			// Core deliberately refreshes a successful REST nonce in X-WP-Nonce. Scan every other reusable value.
			$credentials = array( $cookie, $app_password, $basic_header, $bearer, $invalid_nonce, $invalid_app, $invalid_basic_header, $alternate_token );

			$base = array(
				'user_a_id'                 => $user_ids['user_a_id'],
				'user_b_id'                 => $user_ids['user_b_id'],
				'shared_fixture_credential' => $bearer,
				'origin'                    => 'https://client.example.test',
			);

			$responses['missing']                 = self::request( $base + array( 'route' => 'protected' ) );
			$responses['invalid']                 = self::request(
				$base + array(
					'route'         => 'protected',
					'case'          => 'invalid',
					'authorization' => 'Bearer ' . $bearer,
				)
			);
			$responses['invalid_transport']       = self::request(
				$base + array(
					'route' => 'protected',
					'query' => array( 'access_token' => $alternate_token ),
				)
			);
			$responses['insufficient']            = self::request(
				$base + array(
					'route'         => 'protected',
					'case'          => 'insufficient',
					'authorization' => 'Bearer ' . $bearer,
				)
			);
			$responses['valid']                   = self::request(
				$base + array(
					'route'         => 'protected',
					'case'          => 'valid',
					'authorization' => 'Bearer ' . $bearer,
				)
			);
			$responses['denied']                  = self::request(
				$base + array(
					'route'         => 'denied',
					'case'          => 'valid',
					'authorization' => 'Bearer ' . $bearer,
				)
			);
			$responses['cookie']                  = self::request(
				$base + array(
					'route'  => 'protected',
					'cookie' => $cookie_header,
					'nonce'  => $nonce,
				)
			);
			$responses['app']                     = self::request(
				$base + array(
					'route'      => 'protected',
					'basic_user' => $user_b->user_login,
					'basic_pass' => $app_password,
				)
			);
			$responses['cookie_core_baseline']    = self::request(
				$base + array(
					'route'    => 'protected',
					'boundary' => 'core',
					'cookie'   => $cookie_header,
					'nonce'    => $nonce,
				)
			);
			$responses['app_core_baseline']       = self::request(
				$base + array(
					'route'      => 'protected',
					'boundary'   => 'core',
					'basic_user' => $user_b->user_login,
					'basic_pass' => $app_password,
				)
			);
			$responses['mixed']                   = self::request(
				$base + array(
					'route'         => 'protected',
					'case'          => 'valid',
					'cookie'        => $cookie_header,
					'nonce'         => $nonce,
					'authorization' => 'Bearer ' . $bearer,
				)
			);
			$responses['missing_nonce_baseline']  = self::request(
				$base + array(
					'route'  => 'protected',
					'cookie' => $cookie_header,
				)
			);
			$responses['missing_nonce_bearer']    = self::request(
				$base + array(
					'route'         => 'protected',
					'case'          => 'valid',
					'cookie'        => $cookie_header,
					'authorization' => 'Bearer ' . $bearer,
				)
			);
			$responses['multi_allow']             = self::request(
				$base + array(
					'route'         => 'multi',
					'case'          => 'valid',
					'authorization' => 'Bearer ' . $bearer,
				)
			);
			$responses['public_baseline']         = self::request(
				$base + array(
					'route'  => 'public',
					'cookie' => $cookie_header,
					'nonce'  => $nonce,
				)
			);
			$responses['public_core_baseline']    = self::request(
				$base + array(
					'route'    => 'public',
					'boundary' => 'core',
					'cookie'   => $cookie_header,
					'nonce'    => $nonce,
				)
			);
			$responses['anonymous_core_baseline'] = self::request(
				$base + array(
					'route'    => 'protected',
					'boundary' => 'core',
				)
			);
			$responses['public_mixed']            = self::request(
				$base + array(
					'route'         => 'public',
					'case'          => 'valid',
					'cookie'        => $cookie_header,
					'nonce'         => $nonce,
					'authorization' => 'Bearer ' . $bearer,
				)
			);
			$responses['invalid_nonce_baseline']  = self::request(
				$base + array(
					'route'  => 'protected',
					'cookie' => $cookie_header,
					'nonce'  => $invalid_nonce,
				)
			);
			$responses['invalid_nonce_mixed']     = self::request(
				$base + array(
					'route'         => 'protected',
					'case'          => 'valid',
					'cookie'        => $cookie_header,
					'nonce'         => $invalid_nonce,
					'authorization' => 'Bearer ' . $bearer,
				)
			);
			$responses['invalid_app_baseline']    = self::request(
				$base + array(
					'route'      => 'protected',
					'basic_user' => $user_b->user_login,
					'basic_pass' => $invalid_app,
				)
			);
			$responses['invalid_app_mixed']       = self::request(
				$base + array(
					'route'      => 'protected',
					'query'      => array( 'access_token' => $alternate_token ),
					'basic_user' => $user_b->user_login,
					'basic_pass' => $invalid_app,
				)
			);

			$checks = self::checks( $responses, $credentials );
		} finally {
			wp_set_current_user( $prior_user );
			$cleanup = $users->cleanup();
		}

		$checks['exact_cleanup_complete'] = $cleanup;

		return FixtureContract::httpResult( $checks );
	}

	/**
	 * Performs one bounded request without logging headers or bodies.
	 *
	 * @param array<string, mixed> $request_case Request case.
	 * @return array{status: int, headers: array<string, string>, body: string, json: mixed, bounded: bool}
	 */
	private static function request( array $request_case ): array {
		$route   = is_string( $request_case['route'] ?? null ) ? $request_case['route'] : '';
		$query   = is_array( $request_case['query'] ?? null ) ? $request_case['query'] : array();
		$query   = array(
			'p2_route'    => $route,
			'p2_boundary' => is_string( $request_case['boundary'] ?? null ) ? $request_case['boundary'] : 'proof',
		) + $query;
		$url     = self::ENDPOINT . '?' . http_build_query( $query, '', '&', PHP_QUERY_RFC3986 );
		$headers = array(
			'Accept'                          => 'application/json',
			'Host'                            => 'localhost:8891',
			'X-Charter-P2-User-A'             => (string) ( $request_case['user_a_id'] ?? 0 ),
			'X-Charter-P2-User-B'             => (string) ( $request_case['user_b_id'] ?? 0 ),
			'X-Charter-P2-Case'               => is_string( $request_case['case'] ?? null ) ? $request_case['case'] : 'none',
			'X-Charter-P2-Fixture-Credential' => is_string( $request_case['fixture_credential'] ?? null )
				? $request_case['fixture_credential']
				: (string) ( $request_case['shared_fixture_credential'] ?? '' ),
		);

		foreach ( array(
			'authorization' => 'Authorization',
			'cookie'        => 'Cookie',
			'nonce'         => 'X-WP-Nonce',
			'origin'        => 'Origin',
		) as $key => $name ) {
			if ( is_string( $request_case[ $key ] ?? null ) ) {
				$headers[ $name ] = $request_case[ $key ];
			}
		}

		if ( is_string( $request_case['basic_user'] ?? null ) && is_string( $request_case['basic_pass'] ?? null ) ) {
			// phpcs:ignore WordPress.PHP.DiscouragedPHPFunctions.obfuscation_base64_encode -- HTTP Basic requires base64 by protocol; the header stays private.
			$headers['Authorization'] = 'Basic ' . base64_encode( $request_case['basic_user'] . ':' . $request_case['basic_pass'] );
		}

		$response = wp_remote_get(
			$url,
			array(
				'blocking'            => true,
				'headers'             => $headers,
				'limit_response_size' => self::MAX_RESPONSE_BYTES,
				'redirection'         => 0,
				'timeout'             => self::REQUEST_TIMEOUT_SECONDS,
			)
		);

		if ( is_wp_error( $response ) ) {
			return array(
				'status'  => 0,
				'headers' => array(),
				'body'    => '',
				'json'    => null,
				'bounded' => false,
			);
		}

		$response_headers = array();
		foreach ( wp_remote_retrieve_headers( $response ) as $name => $value ) {
			$response_headers[ strtolower( (string) $name ) ] = is_array( $value ) ? implode( ', ', $value ) : (string) $value;
		}

		$body    = wp_remote_retrieve_body( $response );
		$status  = wp_remote_retrieve_response_code( $response );
		$bounded = strlen( $body ) <= self::MAX_RESPONSE_BYTES;

		$json = null;
		if ( $bounded ) {
			try {
				$json = json_decode( $body, true, 16, JSON_THROW_ON_ERROR );
			} catch ( Throwable ) {
				$json = null;
			}
		}

		return array(
			'status'  => $status,
			'headers' => $response_headers,
			'body'    => $body,
			'json'    => $json,
			'bounded' => $bounded,
		);
	}

	/**
	 * Builds the fixed HTTP check map.
	 *
	 * @param array<string, array<string, mixed>> $responses   Sanitized in-memory responses.
	 * @param array<string>                       $credentials Private credentials.
	 * @return array<string, bool>
	 */
	private static function checks( array $responses, array $credentials ): array {
		$missing                = $responses['missing'];
		$invalid                = $responses['invalid'];
		$transport              = $responses['invalid_transport'];
		$insufficient           = $responses['insufficient'];
		$valid                  = $responses['valid'];
		$denied                 = $responses['denied'];
		$mixed                  = $responses['mixed'];
		$public                 = $responses['public_mixed'];
		$invalid_nonce_baseline = $responses['invalid_nonce_baseline'];
		$invalid_nonce_mixed    = $responses['invalid_nonce_mixed'];
		$invalid_app_baseline   = $responses['invalid_app_baseline'];
		$invalid_app_mixed      = $responses['invalid_app_mixed'];
		$missing_nonce_baseline = $responses['missing_nonce_baseline'];
		$missing_nonce_bearer   = $responses['missing_nonce_bearer'];
		$multi_allow            = $responses['multi_allow'];

		$checks = array(
			'wordpress_6_9_5'                            => '6.9.5' === ( $GLOBALS['wp_version'] ?? null ),
			'missing_bearer_challenge_exact'             => self::hasCode( $missing, 401, 'rest_not_logged_in' )
				&& self::hasChallenge(
					$missing,
					array(
						'resource_metadata' => self::RESOURCE_METADATA,
						'scope'             => SyntheticBearerFixtures::GENERAL_SCOPE,
					)
				),
			'invalid_bearer_challenge_exact'             => self::hasCode( $invalid, 401, 'invalid_token' )
				&& self::hasChallenge(
					$invalid,
					array(
						'error'             => 'invalid_token',
						'resource_metadata' => self::RESOURCE_METADATA,
					)
				),
			'invalid_transport_rejected_400'             => self::hasCode( $transport, 400, 'invalid_request' )
				&& self::hasChallenge(
					$transport,
					array(
						'error'             => 'invalid_request',
						'resource_metadata' => self::RESOURCE_METADATA,
					)
				),
			'insufficient_scope_challenge_exact'         => self::hasCode( $insufficient, 403, 'insufficient_scope' )
				&& self::hasChallenge(
					$insufficient,
					array(
						'error'             => 'insufficient_scope',
						'resource_metadata' => self::RESOURCE_METADATA,
						'scope'             => SyntheticBearerFixtures::GENERAL_SCOPE,
					)
				),
			'oauth_cache_cors_headers_parsed'            => self::sameInfrastructureHeaders(
				$responses['anonymous_core_baseline'],
				$missing,
				$invalid,
				$transport,
				$insufficient
			),
			'valid_bearer_succeeded'                     => self::hasRoute( $valid, 200, 'protected' ) && ! self::hasBearerChallenge( $valid ),
			'wordpress_permission_denial_preserved'      => self::hasCode( $denied, 403, 'rest_forbidden' ) && ! self::hasBearerChallenge( $denied ),
			'assigned_cookie_bearer_rejected_400'        => self::hasCode( $mixed, 400, 'invalid_request' ),
			'assigned_cookie_bearer_invalid_request'     => 'invalid_request' === ( $mixed['json']['code'] ?? null ),
			'assigned_cookie_bearer_resource_metadata_exact' => self::hasChallenge(
				$mixed,
				array(
					'error'             => 'invalid_request',
					'resource_metadata' => self::RESOURCE_METADATA,
				)
			),
			'assigned_cookie_bearer_disclosed_no_detail' => self::hasGenericMixedBody( $mixed ),
			'public_cookie_bearer_inert'                 => self::samePublicResponse( $responses['public_baseline'], $public ),
			'public_cookie_bearer_has_no_challenge'      => ! self::hasBearerChallenge( $public ),
			'public_headers_preserved'                   => self::sameResponseContract( $responses['public_core_baseline'], $responses['public_baseline'] ),
			'invalid_nonce_status_preserved'             => 403 === $invalid_nonce_baseline['status'] && 403 === $invalid_nonce_mixed['status'],
			'invalid_nonce_code_preserved'               => self::sameResponseContract( $invalid_nonce_baseline, $invalid_nonce_mixed )
				&& 'rest_cookie_invalid_nonce' === ( $invalid_nonce_mixed['json']['code'] ?? null ),
			'invalid_nonce_has_no_bearer_challenge'      => ! self::hasBearerChallenge( $invalid_nonce_baseline ) && ! self::hasBearerChallenge( $invalid_nonce_mixed ),
			'invalid_application_password_preserved'     => self::sameResponseContract( $invalid_app_baseline, $invalid_app_mixed )
				&& 401 === $invalid_app_mixed['status'],
			'invalid_application_password_has_no_bearer_challenge' => ! self::hasBearerChallenge( $invalid_app_baseline ) && ! self::hasBearerChallenge( $invalid_app_mixed ),
			'cookie_without_bearer_preserved'            => self::hasRoute( $responses['cookie'], 200, 'protected' ) && ! self::hasBearerChallenge( $responses['cookie'] ),
			'application_password_without_bearer_preserved' => self::hasRoute( $responses['app'], 200, 'protected' ) && ! self::hasBearerChallenge( $responses['app'] ),
			'cookie_headers_preserved'                   => self::sameResponseContract( $responses['cookie_core_baseline'], $responses['cookie'] ),
			'application_password_headers_preserved'     => self::sameResponseContract( $responses['app_core_baseline'], $responses['app'] ),
			'missing_nonce_anonymized_before_boundary'   => self::hasCode( $missing_nonce_baseline, 401, 'rest_not_logged_in' )
				&& self::hasChallenge(
					$missing_nonce_baseline,
					array(
						'resource_metadata' => self::RESOURCE_METADATA,
						'scope'             => SyntheticBearerFixtures::GENERAL_SCOPE,
					)
				),
			'missing_nonce_bearer_uses_bearer_only'      => self::hasRoute( $missing_nonce_bearer, 200, 'protected' ) && ! self::hasBearerChallenge( $missing_nonce_bearer ),
			'multi_handler_allow_exact'                  => self::hasRoute( $multi_allow, 200, 'multi-get' )
				&& 'GET' === ( $multi_allow['headers']['allow'] ?? null ),
			'request_timeouts_finite'                    => self::allBounded( $responses ),
			'credentials_private'                        => self::credentialsAbsent( $responses, $credentials ),
		);

		return $checks;
	}

	/**
	 * Checks an exact REST status and error code.
	 *
	 * @param array<string, mixed> $response REST response.
	 * @param int                  $status   Expected HTTP status.
	 * @param string               $code     Expected REST code.
	 */
	private static function hasCode( array $response, int $status, string $code ): bool {
		return $response['status'] === $status && ( $response['json']['code'] ?? null ) === $code;
	}

	/**
	 * Checks an exact successful proof route response.
	 *
	 * @param array<string, mixed> $response REST response.
	 * @param int                  $status   Expected HTTP status.
	 * @param string               $route    Expected route label.
	 */
	private static function hasRoute( array $response, int $status, string $route ): bool {
		return $response['status'] === $status && ( $response['json']['route'] ?? null ) === $route;
	}

	/**
	 * Checks exact Bearer challenge parameters.
	 *
	 * @param array<string, mixed>  $response   REST response.
	 * @param array<string, string> $parameters Expected parameters.
	 */
	private static function hasChallenge( array $response, array $parameters ): bool {
		$challenge = $response['headers']['www-authenticate'] ?? null;

		return is_string( $challenge ) && ChallengeParser::isExact( $challenge, $parameters );
	}

	/**
	 * Checks whether a response carries a Bearer challenge.
	 *
	 * @param array<string, mixed> $response REST response.
	 */
	private static function hasBearerChallenge( array $response ): bool {
		$challenge = $response['headers']['www-authenticate'] ?? null;

		return is_string( $challenge ) && str_starts_with( $challenge, 'Bearer' );
	}

	/**
	 * Checks the mixed rejection contains only generic REST error fields.
	 *
	 * @param array<string, mixed> $response REST response.
	 */
	private static function hasGenericMixedBody( array $response ): bool {
		$json = $response['json'];
		if (
			! is_array( $json )
			|| array_keys( $json ) !== array( 'code', 'message', 'data' )
			|| 'Use either WordPress authentication or Bearer authentication, not both.' !== ( $json['message'] ?? null )
			|| array( 'status' => 400 ) !== ( $json['data'] ?? null )
		) {
			return false;
		}

		$body = $response['body'];
		return is_string( $body )
			&& ! str_contains( $body, 'permission' )
			&& ! str_contains( $body, 'callback' )
			&& ! str_contains( $body, 'validation' );
	}

	/**
	 * Compares public response semantics with and without Bearer input.
	 *
	 * @param array<string, mixed> $baseline  Baseline response.
	 * @param array<string, mixed> $candidate Bearer-bearing response.
	 */
	private static function samePublicResponse( array $baseline, array $candidate ): bool {
		return 200 === $baseline['status']
			&& $baseline['status'] === $candidate['status']
			&& $baseline['json'] === $candidate['json']
			&& self::relevantHeaders( $baseline ) === self::relevantHeaders( $candidate );
	}

	/**
	 * Compares status, body, and stable cache/CORS/security headers.
	 *
	 * @param array<string, mixed> $baseline Core-only response.
	 * @param array<string, mixed> $candidate Proof-boundary response.
	 */
	private static function sameResponseContract( array $baseline, array $candidate ): bool {
		return $baseline['status'] === $candidate['status']
			&& $baseline['json'] === $candidate['json']
			&& self::relevantHeaders( $baseline ) === self::relevantHeaders( $candidate );
	}

	/**
	 * Selects stable emitted headers whose ownership must remain with Core.
	 *
	 * @param array<string, mixed> $response Captured response.
	 * @return array<string, string>
	 */
	private static function relevantHeaders( array $response ): array {
		$headers  = is_array( $response['headers'] ?? null ) ? $response['headers'] : array();
		$names    = array(
			'access-control-allow-credentials',
			'access-control-allow-headers',
			'access-control-allow-methods',
			'access-control-allow-origin',
			'access-control-expose-headers',
			'allow',
			'cache-control',
			'content-type',
			'expires',
			'link',
			'vary',
			'www-authenticate',
			'x-wp-nonce',
			'x-content-type-options',
			'x-robots-tag',
		);
		$relevant = array();
		foreach ( $names as $name ) {
			if ( is_string( $headers[ $name ] ?? null ) ) {
				$relevant[ $name ] = $headers[ $name ];
			}
		}

		return $relevant;
	}

	/**
	 * Compares emitted cache, CORS, content, and security headers.
	 *
	 * Response-owned Allow and authentication challenge headers are excluded;
	 * they are asserted separately by their exact contracts.
	 *
	 * @param array<string, mixed> $baseline   Core-only anonymous response.
	 * @param array<string, mixed> ...$responses Proof-boundary responses.
	 */
	private static function sameInfrastructureHeaders( array $baseline, array ...$responses ): bool {
		$expected = self::infrastructureHeaders( $baseline );
		foreach ( array( 'access-control-allow-credentials', 'access-control-allow-origin', 'access-control-expose-headers', 'content-type', 'x-content-type-options' ) as $required ) {
			if ( ! is_string( $expected[ $required ] ?? null ) || '' === $expected[ $required ] ) {
				return false;
			}
		}

		foreach ( $responses as $response ) {
			if ( self::infrastructureHeaders( $response ) !== $expected ) {
				return false;
			}
		}

		return true;
	}

	/**
	 * Selects stable infrastructure headers from one captured response.
	 *
	 * @param array<string, mixed> $response Captured response.
	 * @return array<string, string>
	 */
	private static function infrastructureHeaders( array $response ): array {
		$headers  = is_array( $response['headers'] ?? null ) ? $response['headers'] : array();
		$names    = array(
			'access-control-allow-credentials',
			'access-control-allow-headers',
			'access-control-allow-methods',
			'access-control-allow-origin',
			'access-control-expose-headers',
			'cache-control',
			'content-type',
			'expires',
			'vary',
			'x-content-type-options',
			'x-robots-tag',
		);
		$selected = array();
		foreach ( $names as $name ) {
			if ( is_string( $headers[ $name ] ?? null ) ) {
				$selected[ $name ] = $headers[ $name ];
			}
		}

		return $selected;
	}

	/**
	 * Compares exact decoded REST bodies.
	 *
	 * @param array<string, mixed> $baseline  Baseline response.
	 * @param array<string, mixed> $candidate Candidate response.
	 */
	private static function sameJson( array $baseline, array $candidate ): bool {
		return is_array( $baseline['json'] ) && $baseline['json'] === $candidate['json'];
	}

	/**
	 * Checks that every response respected the fixed request/output bounds.
	 *
	 * @param array<string, array<string, mixed>> $responses REST responses.
	 */
	private static function allBounded( array $responses ): bool {
		foreach ( $responses as $response ) {
			if ( true !== ( $response['bounded'] ?? false ) ) {
				return false;
			}
		}

		return array() !== $responses;
	}

	/**
	 * Checks no private authentication value appears in response material.
	 *
	 * @param array<string, array<string, mixed>> $responses   REST responses.
	 * @param array<string>                       $credentials Private values.
	 */
	private static function credentialsAbsent( array $responses, array $credentials ): bool {
		$visible = '';
		foreach ( $responses as $response ) {
			$visible .= (string) ( $response['body'] ?? '' );
			foreach ( $response['headers'] ?? array() as $value ) {
				$visible .= (string) $value;
			}
		}

		foreach ( $credentials as $credential ) {
			if ( '' === $credential || str_contains( $visible, $credential ) ) {
				return false;
			}
		}

		return true;
	}

	/**
	 * Prevents construction.
	 */
	private function __construct() {}
}

$charter_p2_http_runner_args = isset( $args ) && is_array( $args ) ? $args : array();
$charter_p2_http_runner_id   = is_string( $charter_p2_http_runner_args[0] ?? null ) ? $charter_p2_http_runner_args[0] : '';

try {
	$charter_p2_http_runner_result = HttpRunner::run( $charter_p2_http_runner_id );
} catch ( Throwable ) {
	$charter_p2_http_runner_result = FixtureContract::httpFailure();
}

// phpcs:ignore WordPress.WP.AlternativeFunctions.json_encode_json_encode -- Emits one public fixed boolean-only HTTP record.
echo json_encode( $charter_p2_http_runner_result, JSON_THROW_ON_ERROR );
echo "\n";
exit( $charter_p2_http_runner_result['passed'] ? 0 : 1 );
