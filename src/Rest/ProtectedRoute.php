<?php
/**
 * Protected REST route declaration API.
 *
 * @package GalatanOvidiu\Charter
 */

declare(strict_types=1);

namespace GalatanOvidiu\Charter\Rest;

use GalatanOvidiu\Charter\OAuth\AuthorizationService;
use Throwable;
use WP_REST_Request;

/**
 * Marks only the exact handler WordPress later selects for dispatch.
 *
 * @since 0.1.0
 */
final class ProtectedRoute {

	private const ATTRIBUTE                = 'charter_oauth_protection';
	public const CALLBACK_EXCEPTION_ACTION = 'charter_oauth_rest_callback_exception';

	/**
	 * Adds default-resource OAuth protection to a route handler.
	 *
	 * @since 0.1.0
	 *
	 * @param array<string, mixed> $handler        Ordinary register_rest_route handler.
	 * @param array<string>        $requiredScopes Required scopes.
	 * @param string               $resourceIdentifier Default sentinel or exact resource.
	 * @return array<string, mixed> Decorated handler.
	 */
	public static function assign(
		array $handler,
		array $requiredScopes = array( AuthorizationService::GENERAL_SCOPE ),
		string $resourceIdentifier = RouteAssignment::DEFAULT_RESOURCE
	): array {
		$handler[ self::ATTRIBUTE ] = new RouteAssignment( $resourceIdentifier, $requiredScopes );
		foreach ( array( 'permission_callback', 'callback' ) as $callbackKey ) {
			$callback = $handler[ $callbackKey ] ?? null;
			if ( is_callable( $callback ) ) {
				$handler[ $callbackKey ] = self::cleanupOnException( $callback );
			}
		}

		return $handler;
	}

	/**
	 * Returns the assignment on one exact Core-selected handler.
	 *
	 * @since 0.1.0
	 *
	 * @param array<string, mixed> $handler Selected REST handler.
	 */
	public static function assignmentFor( array $handler ): ?RouteAssignment {
		$assignment = $handler[ self::ATTRIBUTE ] ?? null;

		return $assignment instanceof RouteAssignment ? $assignment : null;
	}

	/**
	 * Ensures an exceptional route callback cannot strand Bearer identity.
	 *
	 * @since 0.1.0
	 *
	 * @param callable $callback Registered WordPress callback.
	 */
	private static function cleanupOnException( callable $callback ): callable {
		return static function ( WP_REST_Request $request ) use ( $callback ): mixed {
			try {
				return call_user_func( $callback, $request );
			} catch ( Throwable $throwable ) {
				do_action( self::CALLBACK_EXCEPTION_ACTION, $request ); // phpcs:ignore WordPress.NamingConventions.PrefixAllGlobals.DynamicHooknameFound -- The constant is the fixed charter_oauth-prefixed internal hook.
				throw $throwable;
			}
		};
	}

	/**
	 * This class contains static declaration mechanics only.
	 */
	private function __construct() {
	}
}
