<?php
/**
 * OAuth token revocation endpoint controller.
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
 * Exposes RFC 7009 grant-wide token revocation.
 *
 * @since 0.1.0
 */
final class RevocationController {

	private const PARAMETERS = array(
		'token',
		'token_type_hint',
		'client_id',
		'client_secret',
	);

	/**
	 * Creates the revocation controller.
	 *
	 * @since 0.1.0
	 *
	 * @param TokenService $tokens Token lifecycle service.
	 */
	public function __construct(
		private readonly TokenService $tokens
	) {
	}

	/**
	 * Registers the revocation endpoint.
	 *
	 * @since 0.1.0
	 */
	public function registerRoutes(): void {
		register_rest_route(
			'charter/v1',
			'/revoke',
			array(
				'methods'             => 'POST',
				'callback'            => array( $this, 'revoke' ),
				'permission_callback' => '__return_true',
			)
		);
	}

	/**
	 * Revokes a token family and returns the non-revealing RFC 7009 result.
	 *
	 * @since 0.1.0
	 *
	 * @param WP_REST_Request $request Revocation request.
	 * @throws ProtocolException Internally normalized to an OAuth response.
	 */
	public function revoke( WP_REST_Request $request ): WP_REST_Response {
		try {
			if ( '' !== (string) $request->get_header( 'authorization' ) ) {
				throw new ProtocolException( 'invalid_client', 'Client authentication failed.', 401 );
			}

			$contentType = (string) $request->get_header( 'content-type' );
			if ( 1 !== preg_match( '/^application\/x-www-form-urlencoded(?:\s*;|$)/i', $contentType ) ) {
				throw new ProtocolException( 'invalid_request', 'The revocation request must be form encoded.' );
			}

			$body = (string) $request->get_body();
			if ( strlen( $body ) > 16384 || self::hasDuplicateParameters( $body ) ) {
				throw new ProtocolException( 'invalid_request', 'The revocation request contains invalid or duplicate parameters.' );
			}

			$this->tokens->revoke( $request->get_body_params() );
			$response = new WP_REST_Response( null, 200 );
		} catch ( ProtocolException $exception ) {
			$response = new WP_REST_Response(
				array(
					'error'             => $exception->error(),
					'error_description' => $exception->getMessage(),
				),
				$exception->status()
			);
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
