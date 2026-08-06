<?php
/**
 * RFC 7591 Dynamic Client Registration HTTP controller.
 *
 * @package GalatanOvidiu\Charter
 */

declare(strict_types=1);

namespace GalatanOvidiu\Charter\Http;

use GalatanOvidiu\Charter\OAuth\Client;
use GalatanOvidiu\Charter\OAuth\DynamicRegistrationException;
use GalatanOvidiu\Charter\OAuth\DynamicRegistrationService;
use WP_REST_Request;
use WP_REST_Response;

/**
 * Projects immutable DCR success and bounded protocol errors without CORS.
 *
 * @since 0.1.0
 */
final class RegistrationController {

	/**
	 * Creates the registration controller.
	 *
	 * @param DynamicRegistrationService $registration Registration service.
	 */
	public function __construct(
		private readonly DynamicRegistrationService $registration
	) {
	}

	/** Registers the public POST endpoint. */
	public function registerRoutes(): void {
		register_rest_route(
			'charter/v1',
			'/register',
			array(
				'methods'             => 'POST',
				'callback'            => array( $this, 'register' ),
				'permission_callback' => '__return_true',
			)
		);
	}

	/**
	 * Handles one JSON registration request.
	 *
	 * @param WP_REST_Request $request Current request.
	 */
	public function register( WP_REST_Request $request ): WP_REST_Response {
		$contentType   = strtolower( trim( explode( ';', (string) $request->get_header( 'content-type' ), 2 )[0] ) );
		$authorization = $request->get_header( 'authorization' );
		if ( 'application/json' !== $contentType || ( null !== $authorization && '' !== $authorization ) ) {
			return $this->errorResponse( 'invalid_client_metadata', 'The registration request is invalid.', 400 );
		}

		try {
			$registered = $this->registration->register( $request->get_body() );
		} catch ( DynamicRegistrationException $exception ) {
			return $this->errorResponse( $exception->error(), $exception->getMessage(), $exception->status(), $exception->retryAfter() );
		}

		$client = $registered['client'];
		$data   = array(
			'client_id'                  => $client->clientId(),
			'client_id_issued_at'        => $registered['issued_at'],
			'client_name'                => $client->name(),
			'redirect_uris'              => $client->redirectUris(),
			'token_endpoint_auth_method' => $client->authenticationMethod(),
			'grant_types'                => array_values(
				array_filter(
					array( Client::GRANT_AUTHORIZATION_CODE, Client::GRANT_REFRESH_TOKEN ),
					static fn ( string $grantType ): bool => $client->supportsGrantType( $grantType )
				)
			),
			'response_types'             => array( 'code' ),
		);
		if ( is_string( $registered['client_secret'] ) ) {
			$data['client_secret']            = $registered['client_secret'];
			$data['client_secret_expires_at'] = 0;
		}

		$response = new WP_REST_Response( $data, 201 );
		$response->header( 'Cache-Control', 'no-store' );
		$response->header( 'Pragma', 'no-cache' );

		return $response;
	}

	/**
	 * Creates one no-store protocol error response.
	 *
	 * @param string   $error Protocol error.
	 * @param string   $description Public description.
	 * @param int      $status HTTP status.
	 * @param int|null $retryAfter Retry delay.
	 */
	private function errorResponse( string $error, string $description, int $status, ?int $retryAfter = null ): WP_REST_Response {
		$response = new WP_REST_Response(
			array(
				'error'             => $error,
				'error_description' => $description,
			),
			$status
		);
		$response->header( 'Cache-Control', 'no-store' );
		$response->header( 'Pragma', 'no-cache' );
		if ( is_int( $retryAfter ) ) {
			$response->header( 'Retry-After', (string) max( 1, $retryAfter ) );
		}

		return $response;
	}
}
