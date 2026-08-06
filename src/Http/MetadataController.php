<?php
/**
 * OAuth metadata HTTP controller.
 *
 * @package GalatanOvidiu\Charter
 */

declare(strict_types=1);

namespace GalatanOvidiu\Charter\Http;

use GalatanOvidiu\Charter\OAuth\AuthorizationService;
use GalatanOvidiu\Charter\OAuth\AccessPolicyProvider;
use GalatanOvidiu\Charter\OAuth\DynamicRegistrationService;
use GalatanOvidiu\Charter\OAuth\EmergencyContainment;
use GalatanOvidiu\Charter\Site\SiteState;
use WP_Error;
use WP_REST_Request;
use WP_REST_Response;

/**
 * Publishes truthful RFC 8414 and exact-resource RFC 9728 metadata.
 *
 * @since 0.1.0
 */
final class MetadataController {

	/**
	 * Creates the metadata controller.
	 *
	 * @since 0.1.0
	 *
	 * @param SiteState            $siteState Site lifecycle and identity.
	 * @param AccessPolicyProvider $accessPolicy Active exact resource and scope registrations.
	 * @param EmergencyContainment $containment Issuer-local emergency mode.
	 */
	public function __construct(
		private readonly SiteState $siteState,
		private readonly AccessPolicyProvider $accessPolicy,
		private readonly EmergencyContainment $containment
	) {
	}

	/**
	 * Adds root well-known rewrites.
	 *
	 * @since 0.1.0
	 */
	public function registerRewriteRules(): void {
		add_rewrite_rule(
			'^\.well-known/oauth-authorization-server/?$',
			'index.php?rest_route=/charter/v1/metadata/authorization-server',
			'top'
		);
		add_rewrite_rule(
			'^\.well-known/oauth-protected-resource/?$',
			'index.php?rest_route=/charter/v1/metadata/protected-resource',
			'top'
		);
		add_rewrite_rule(
			'^\.well-known/oauth-protected-resource/(.+)$',
			'index.php?rest_route=/charter/v1/metadata/protected-resource/$matches[1]',
			'top'
		);
	}

	/**
	 * Registers internal REST handlers reached by well-known rewrites.
	 *
	 * @since 0.1.0
	 */
	public function registerRoutes(): void {
		register_rest_route(
			'charter/v1',
			'/metadata/authorization-server',
			array(
				'methods'             => 'GET',
				'callback'            => array( $this, 'authorizationServer' ),
				'permission_callback' => '__return_true',
			)
		);

		register_rest_route(
			'charter/v1',
			'/metadata/protected-resource/(?P<resource_path>.+)',
			array(
				'methods'             => 'GET',
				'callback'            => array( $this, 'protectedResource' ),
				'permission_callback' => '__return_true',
			)
		);

		register_rest_route(
			'charter/v1',
			'/metadata/protected-resource',
			array(
				'methods'             => 'GET',
				'callback'            => array( $this, 'protectedResource' ),
				'permission_callback' => '__return_true',
			)
		);
	}

	/**
	 * Returns RFC 8414 authorization-server metadata.
	 *
	 * @since 0.1.0
	 *
	 * @param WP_REST_Request $request Current request.
	 * @return WP_REST_Response|WP_Error Metadata or a fail-closed not-found response.
	 */
	public function authorizationServer( WP_REST_Request $request ): WP_REST_Response|WP_Error {
		unset( $request );
		$identity = $this->siteState->identity();
		if ( null === $identity || ! $this->siteState->publishesMetadata() || ! $this->siteState->requestMatchesIdentity() ) {
			return new WP_Error( 'rest_no_route', 'No route was found matching the URL and request method.', array( 'status' => 404 ) );
		}

		$data = array( 'issuer' => $identity->issuer() );
		if ( $this->siteState->isEnabled() ) {
			$urls   = new EndpointUrls( $identity->issuer() );
			$policy = $this->accessPolicy->forIssuer( $identity->issuer() );
			$data   = array(
				'issuer'                                => $identity->issuer(),
				'authorization_endpoint'                => $urls->authorizationEndpoint(),
				'token_endpoint'                        => $urls->tokenEndpoint(),
				'revocation_endpoint'                   => $urls->revocationEndpoint(),
				'response_types_supported'              => array( 'code' ),
				'response_modes_supported'              => array( 'query' ),
				'grant_types_supported'                 => array( 'authorization_code', 'refresh_token' ),
				'code_challenge_methods_supported'      => array( 'S256' ),
				'token_endpoint_auth_methods_supported' => array( 'none', 'client_secret_post' ),
				'revocation_endpoint_auth_methods_supported' => array( 'none', 'client_secret_post' ),
				'scopes_supported'                      => array_merge( $policy->scopeIdentifiers(), array( AuthorizationService::OFFLINE_ACCESS_SCOPE ) ),
				'authorization_response_iss_parameter_supported' => true,
				'client_id_metadata_document_supported' => true,
			);
			if ( DynamicRegistrationService::isEnabled() && $this->containment->issuanceAllowed() ) {
				$data['registration_endpoint'] = $urls->registrationEndpoint();
			}
		}

		return $this->metadataResponse( $data );
	}

	/**
	 * Returns RFC 9728 metadata for one registered exact resource.
	 *
	 * @since 0.1.0
	 *
	 * @param WP_REST_Request $request Current request.
	 * @return WP_REST_Response|WP_Error Metadata or a fail-closed not-found response.
	 */
	public function protectedResource( WP_REST_Request $request ): WP_REST_Response|WP_Error {
		$identity = $this->siteState->identity();
		if ( null === $identity || ! $this->siteState->publishesMetadata() || ! $this->siteState->requestMatchesIdentity() ) {
			return new WP_Error( 'rest_no_route', 'No route was found matching the URL and request method.', array( 'status' => 404 ) );
		}

		$resourcePath = $request->get_param( 'resource_path' );
		$resourcePath = is_string( $resourcePath ) ? ltrim( $resourcePath, '/' ) : '';
		$resource     = '' === $resourcePath ? $identity->issuer() : $identity->issuer() . '/' . $resourcePath;
		$policy       = $this->accessPolicy->forIssuer( $identity->issuer() );
		if ( ! $policy->hasResource( $resource ) ) {
			return new WP_Error( 'rest_no_route', 'No route was found matching the URL and request method.', array( 'status' => 404 ) );
		}

		$data = array( 'resource' => $resource );
		if ( $this->siteState->isEnabled() ) {
			$data = array(
				'resource'                 => $resource,
				'authorization_servers'    => array( $identity->issuer() ),
				'bearer_methods_supported' => array( 'header' ),
				'scopes_supported'         => $policy->scopesForResource( $resource ),
			);
		}

		return $this->metadataResponse( $data );
	}

	/**
	 * Creates a public, non-credentialed, non-cacheable metadata response.
	 *
	 * @since 0.1.0
	 *
	 * @param array<string, mixed> $data Metadata document.
	 */
	private function metadataResponse( array $data ): WP_REST_Response {
		$response = new WP_REST_Response( $data, 200 );
		$response->header( 'Access-Control-Allow-Origin', '*' );
		$response->header( 'Cache-Control', 'no-store' );
		$response->header( 'Pragma', 'no-cache' );

		return $response;
	}
}
