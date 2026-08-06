<?php
/**
 * OAuth endpoint CORS policy.
 *
 * @package GalatanOvidiu\Charter
 */

declare(strict_types=1);

namespace GalatanOvidiu\Charter\Http;

use WP_REST_Request;

/**
 * Restores Charter's route-specific wire contract after WordPress Core CORS.
 *
 * @since 0.1.0
 */
final class CorsPolicy {

	private const METADATA_ROUTES = array(
		'/charter/v1/metadata/authorization-server',
		'/charter/v1/metadata/protected-resource',
	);

	private const NO_CORS_ROUTES = array(
		'/charter/v1/register',
		'/charter/v1/revoke',
		'/charter/v1/token',
	);

	/**
	 * Registers late wire-header normalization.
	 *
	 * @since 0.1.0
	 */
	public function registerHooks(): void {
		add_filter( 'rest_pre_serve_request', array( $this, 'apply' ), 20, 4 );
	}

	/**
	 * Publishes wildcard non-credentialed metadata CORS and no credential CORS.
	 *
	 * @since 0.1.0
	 *
	 * @param mixed           $served  Whether another filter served the request.
	 * @param mixed           $result  REST response, unused.
	 * @param WP_REST_Request $request Current REST request.
	 * @param mixed           $server  REST server, unused.
	 * @return mixed Unchanged served state.
	 */
	public function apply( mixed $served, mixed $result, WP_REST_Request $request, mixed $server ): mixed {
		unset( $result, $server );

		$route = $request->get_route();
		if ( ! in_array( $route, self::METADATA_ROUTES, true ) && ! in_array( $route, self::NO_CORS_ROUTES, true ) ) {
			return $served;
		}

		self::removeCoreCorsHeaders();
		if ( in_array( $route, self::METADATA_ROUTES, true ) ) {
			header( 'Access-Control-Allow-Origin: *' );
		}

		return $served;
	}

	/**
	 * Removes the generic credentialed REST CORS headers Core emitted.
	 *
	 * @since 0.1.0
	 */
	private static function removeCoreCorsHeaders(): void {
		foreach (
			array(
				'Access-Control-Allow-Origin',
				'Access-Control-Allow-Methods',
				'Access-Control-Allow-Credentials',
				'Access-Control-Allow-Headers',
				'Access-Control-Expose-Headers',
				'Vary',
			) as $headerName
		) {
			header_remove( $headerName );
		}
	}
}
