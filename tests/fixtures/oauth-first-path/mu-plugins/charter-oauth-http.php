<?php
/**
 * Focused real-HTTP routes for the first production OAuth path.
 *
 * @package GalatanOvidiu\Charter
 */

declare(strict_types=1);

use GalatanOvidiu\Charter\Plugin;
use GalatanOvidiu\Charter\Rest\ProtectedRoute;

add_action(
	'rest_api_init',
	static function (): void {
		if ( ! class_exists( ProtectedRoute::class ) ) {
			return;
		}

		register_rest_route(
			'charter-http/v1',
			'/public',
			array(
				'methods'             => 'GET',
				'permission_callback' => '__return_true',
				'callback'            => static fn (): array => array( 'public' => true ),
			)
		);

		register_rest_route(
			'charter-http/v1',
			'/protected',
			ProtectedRoute::assign(
				array(
					'methods'             => 'GET',
					'permission_callback' => static fn (): bool => current_user_can( 'read' ),
					'callback'            => static function (): array {
						$context = Plugin::boot()->bearerAuthenticator()->currentContext();

						return array(
							'user_id'   => get_current_user_id(),
							'client_id' => null === $context ? null : $context->clientId(),
							'resource'  => null === $context ? null : $context->resource(),
						);
					},
				)
			)
		);
	}
);
