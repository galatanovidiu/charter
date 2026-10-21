<?php
/**
 * OAuth token endpoint controller.
 *
 * @package GalatanOvidiu\Charter
 */

declare(strict_types=1);

namespace GalatanOvidiu\Charter\Http;

use GalatanOvidiu\Charter\OAuth\ProtocolException;
use GalatanOvidiu\Charter\OAuth\TokenService;
use WP_REST_Request;
use WP_REST_Response;

/**
 * Exposes form-encoded public-client authorization-code exchange.
 *
 * @since 0.1.0
 */
final class TokenController {
	private const PARAMETERS = array(
		'grant_type',
		'client_id',
		'client_secret',
		'code',
		'code_verifier',
		'redirect_uri',
		'resource',
		'refresh_token',
		'scope',
	);

	/**
	 * Creates the token controller.
	 *
	 * @since 0.1.0
	 *
	 * @param TokenService $tokens Token service.
	 */
	public function __construct(
		private readonly TokenService $tokens
	) {
	}

	/**
	 * Registers the token endpoint.
	 *
	 * @since 0.1.0
	 */
	public function registerRoutes(): void {
		register_rest_route(
			'charter/v1',
			'/token',
			array(
				'methods'             => 'POST',
				'callback'            => array( $this, 'exchange' ),
				'permission_callback' => '__return_true',
			)
		);
	}

	/**
	 * Exchanges a code and returns a no-store OAuth response.
	 *
	 * @since 0.1.0
	 *
	 * @param WP_REST_Request $request Token request.
	 * @throws ProtocolException Internally normalized to an OAuth response.
	 */
	public function exchange( WP_REST_Request $request ): WP_REST_Response {
		try {
			$authorization = (string) $request->get_header( 'authorization' );
			if ( '' !== $authorization ) {
				throw new ProtocolException( 'invalid_client', 'Client authentication failed.', 401 );
			}

			$contentType = (string) $request->get_header( 'content-type' );
			if ( 1 !== preg_match( '/^application\/x-www-form-urlencoded(?:\s*;|$)/i', $contentType ) ) {
				throw new ProtocolException( 'invalid_request', 'The token request must be form encoded.' );
			}

			$body = (string) $request->get_body();
			if ( strlen( $body ) > 16384 || self::hasDuplicateParameters( $body ) ) {
				throw new ProtocolException( 'invalid_request', 'The token request contains invalid or duplicate parameters.' );
			}

			$parameters = $request->get_body_params();
			$response   = new WP_REST_Response( $this->tokens->exchange( $parameters ), 200 );
		} catch ( ProtocolException $exception ) {
			$response = new WP_REST_Response(
				array(
					'error'             => $exception->error(),
					'error_description' => $exception->getMessage(),
				),
				$exception->status()
			);
			if ( is_int( $exception->retryAfter() ) ) {
				$response->header( 'Retry-After', (string) max( 1, $exception->retryAfter() ) );
			}
		}

		$response->header( 'Cache-Control', 'no-store' );
		$response->header( 'Pragma', 'no-cache' );

		return $response;
	}

	/**
	 * Reports duplicate names in a form-encoded request body.
	 *
	 * @since 0.1.0
	 *
	 * @param string $body Raw form body.
	 */
	private static function hasDuplicateParameters( string $body ): bool {
		$seen = array();
		foreach ( explode( '&', $body ) as $pair ) {
			if ( '' === $pair ) {
				continue;
			}

			$name           = urldecode( explode( '=', $pair, 2 )[0] );
			$normalizedName = str_replace( array( '.', ' ' ), '_', $name );
			if ( $normalizedName !== $name && in_array( $normalizedName, self::PARAMETERS, true ) ) {
				return true;
			}
			if ( isset( $seen[ $name ] ) ) {
				return true;
			}
			$seen[ $name ] = true;
		}

		return false;
	}
}
