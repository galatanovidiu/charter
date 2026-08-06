<?php
/**
 * Focused real-HTTP routes for the first production OAuth path.
 *
 * @package GalatanOvidiu\Charter
 */

declare(strict_types=1);

use GalatanOvidiu\Charter\Plugin;
use GalatanOvidiu\Charter\OAuth\AccessPolicy;
use GalatanOvidiu\Charter\Rest\ProtectedRoute;

add_action(
	'charter_oauth_register_access',
	static function ( AccessPolicy $policy, string $issuer ): void {
		if ( 1 === (int) get_option( 'charter_http_disable_mcp_profile', 0 ) ) {
			return;
		}

		$resource = $issuer . '/wp-json/charter-http/v1/mcp';
		if (
			! $policy->registerResource( 'charter-http-mcp', $resource )
			|| ! $policy->registerScope(
				'charter-http-mcp',
				'charter-http-mcp:access',
				'Charter HTTP MCP access',
				'Use the focused MCP-compatible server as your WordPress account.',
				array( $resource )
			)
		) {
			throw new RuntimeException( 'The focused MCP access profile could not be registered.' );
		}
	},
	10,
	2
);

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

		$identity = Plugin::boot()->siteState()->identity();
		if ( null !== $identity ) {
			register_rest_route(
				'charter-http/v1',
				'/mcp',
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
					),
					array( 'charter-http-mcp:access' ),
					$identity->issuer() . '/wp-json/charter-http/v1/mcp'
				)
			);
		}
	}
);
