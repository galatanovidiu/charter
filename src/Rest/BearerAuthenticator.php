<?php
/**
 * WordPress REST Bearer authentication boundary.
 *
 * @package GalatanOvidiu\Charter
 */

declare(strict_types=1);

namespace GalatanOvidiu\Charter\Rest;

use GalatanOvidiu\Charter\Http\EndpointUrls;
use GalatanOvidiu\Charter\OAuth\AccessPolicyProvider;
use GalatanOvidiu\Charter\OAuth\AccessTokenContext;
use GalatanOvidiu\Charter\OAuth\ProtocolException;
use GalatanOvidiu\Charter\OAuth\TokenService;
use GalatanOvidiu\Charter\Site\SiteState;
use SplObjectStorage;
use WeakMap;
use WP_Error;
use WP_REST_Request;
use WP_REST_Response;
use WP_REST_Server;

/**
 * Authenticates Bearer tokens only after WordPress selects a protected handler.
 *
 * @since 0.1.0
 */
final class BearerAuthenticator {

	private const MISSING_CREDENTIAL = 'charter_oauth_required';
	private const MODE_BEARER        = 'bearer';
	private const MODE_LEGACY        = 'legacy';
	private const MODE_REJECTED      = 'rejected';

	/**
	 * Active request identity frames.
	 *
	 * @var WeakMap<WP_REST_Request, array{prior_user_id: int, prior_context: AccessTokenContext|null, context: AccessTokenContext}>
	 */
	private WeakMap $frames;

	/**
	 * Authentication result retained for WordPress's later Allow-header pass.
	 *
	 * @var WeakMap<WP_REST_Request, string>
	 */
	private WeakMap $requestModes;

	/**
	 * Errors owned by this boundary and eligible for challenge projection.
	 *
	 * @var SplObjectStorage<WP_Error, array{error: string|null, description: string, status: int, scopes: array<string>, resource_metadata: string|null}>
	 */
	private SplObjectStorage $errors;

	/**
	 * Current nested OAuth context.
	 *
	 * @var AccessTokenContext|null
	 */
	private ?AccessTokenContext $currentContext = null;

	/**
	 * Creates the REST boundary.
	 *
	 * @since 0.1.0
	 *
	 * @param SiteState            $siteState Site lifecycle and identity.
	 * @param TokenService         $tokens    Access-token validator.
	 * @param AccessPolicyProvider $accessPolicy Active exact resource and scope registrations.
	 */
	public function __construct(
		private readonly SiteState $siteState,
		private readonly TokenService $tokens,
		private readonly AccessPolicyProvider $accessPolicy
	) {
		$this->frames       = new WeakMap();
		$this->requestModes = new WeakMap();
		$this->errors       = new SplObjectStorage();
	}

	/**
	 * Registers matched-handler hooks.
	 *
	 * @since 0.1.0
	 */
	public function registerHooks(): void {
		add_filter( 'rest_request_before_callbacks', array( $this, 'beforeCallbacks' ), 10, 3 );
		add_filter( 'rest_request_after_callbacks', array( $this, 'afterCallbacks' ), 10, 3 );
		add_action( ProtectedRoute::CALLBACK_EXCEPTION_ACTION, array( $this, 'cleanupAfterCallbackException' ) );
		add_filter( 'rest_post_dispatch', array( $this, 'sendAllowHeader' ), 10, 3 );
		$this->replaceCoreAllowFilter();
		add_action( 'rest_api_init', array( $this, 'replaceCoreAllowFilter' ), PHP_INT_MAX );
	}

	/**
	 * Removes Core's identity-unaware Allow pass after default REST setup.
	 *
	 * @since 0.1.0
	 */
	public function replaceCoreAllowFilter(): void {
		$corePriority = has_filter( 'rest_post_dispatch', 'rest_send_allow_header' );
		if ( is_int( $corePriority ) ) {
			remove_filter( 'rest_post_dispatch', 'rest_send_allow_header', $corePriority );
		}
	}

	/**
	 * Applies OAuth before the selected handler's WordPress permission callback.
	 *
	 * @since 0.1.0
	 *
	 * @param mixed                $response Current response.
	 * @param array<string, mixed> $handler  Core-selected handler.
	 * @param WP_REST_Request      $request  Matched request.
	 * @return mixed Filtered response.
	 */
	public function beforeCallbacks( mixed $response, array $handler, WP_REST_Request $request ): mixed {
		if ( null !== $response ) {
			return $response;
		}

		$assignment = ProtectedRoute::assignmentFor( $handler );
		if ( null === $assignment ) {
			return $response;
		}

		$authorizationHeader = (string) $request->get_header( 'authorization' );
		$hasBearerAttempt    = 1 === preg_match( '/^Bearer(?:\s|$)/i', $authorizationHeader );
		$isWordPressAuth     = get_current_user_id() > 0 && null === $this->currentContext;

		if ( ! $hasBearerAttempt ) {
			$this->requestModes[ $request ] = $isWordPressAuth ? self::MODE_LEGACY : self::MODE_REJECTED;

			return $isWordPressAuth ? $response : $this->error( self::MISSING_CREDENTIAL, null, 'Bearer authentication is required.', 401, $assignment->requiredScopes(), $this->resourceMetadata( $assignment, $request ) );
		}

		if ( $isWordPressAuth ) {
			$this->requestModes[ $request ] = self::MODE_REJECTED;
			return $this->error( 'invalid_request', 'invalid_request', 'Use either WordPress authentication or Bearer authentication, not both.', 400, array(), $this->resourceMetadata( $assignment, $request ) );
		}

		if ( 1 !== preg_match( '/^Bearer ([A-Za-z0-9_-]{20,256})$/Di', $authorizationHeader, $matches ) ) {
			$this->requestModes[ $request ] = self::MODE_REJECTED;
			return $this->error( 'invalid_request', 'invalid_request', 'The request uses invalid Bearer transport.', 400, array(), $this->resourceMetadata( $assignment, $request ) );
		}

		$identity = $this->siteState->identity();
		if ( null === $identity ) {
			$this->requestModes[ $request ] = self::MODE_REJECTED;
			return $this->error( 'invalid_token', 'invalid_token', 'The access token is invalid.', 401, array(), null );
		}

		try {
			$context = $this->tokens->validateAccessToken(
				$matches[1],
				$assignment->resource( $identity->issuer() ),
				$assignment->requiredScopes()
			);
		} catch ( ProtocolException $exception ) {
			$this->requestModes[ $request ] = self::MODE_REJECTED;
			return $this->error(
				$exception->error(),
				$exception->error(),
				$exception->getMessage(),
				$exception->status(),
				'insufficient_scope' === $exception->error() ? $assignment->requiredScopes() : array(),
				$this->resourceMetadata( $assignment, $request )
			);
		}

		$this->frames[ $request ]       = array(
			'prior_user_id' => get_current_user_id(),
			'prior_context' => $this->currentContext,
			'context'       => $context,
		);
		$this->requestModes[ $request ] = self::MODE_BEARER;
		$this->currentContext           = $context;
		wp_set_current_user( $context->userId() );

		return $response;
	}

	/**
	 * Restores WordPress identity and projects exact RFC 6750 challenges.
	 *
	 * @since 0.1.0
	 *
	 * @param mixed                $response Current response.
	 * @param array<string, mixed> $handler  Core-selected handler.
	 * @param WP_REST_Request      $request  Matched request.
	 * @return mixed Filtered response.
	 */
	public function afterCallbacks( mixed $response, array $handler, WP_REST_Request $request ): mixed {
		unset( $handler );
		$this->cleanupRequest( $request );

		if ( ! $response instanceof WP_Error || ! $this->errors->contains( $response ) ) {
			return $response;
		}

		$details = $this->errors[ $response ];
		$this->errors->detach( $response );
		$body      = array(
			'error'             => null === $details['error'] ? 'invalid_token' : $details['error'],
			'error_description' => $details['description'],
		);
		$projected = new WP_REST_Response( $body, $details['status'] );
		$projected->header( 'WWW-Authenticate', self::challenge( $details['error'], $details['scopes'], $details['resource_metadata'] ) );

		return $projected;
	}

	/**
	 * Returns the current validated OAuth context during route callbacks.
	 *
	 * @since 0.1.0
	 */
	public function currentContext(): ?AccessTokenContext {
		return $this->currentContext;
	}

	/**
	 * Restores identity when a protected callback exits exceptionally.
	 *
	 * @since 0.1.0
	 *
	 * @param WP_REST_Request $request Matched request.
	 */
	public function cleanupAfterCallbackException( WP_REST_Request $request ): void {
		$this->cleanupRequest( $request );
		unset( $this->requestModes[ $request ] );
	}

	/**
	 * Rebuilds Core's Allow response without rerunning protected permissions
	 * under a cleaned-up or rejected identity.
	 *
	 * @since 0.1.0
	 *
	 * @param WP_REST_Response $response Current response.
	 * @param WP_REST_Server   $server   REST server.
	 * @param WP_REST_Request  $request  Matched request.
	 */
	public function sendAllowHeader( WP_REST_Response $response, WP_REST_Server $server, WP_REST_Request $request ): WP_REST_Response {
		$matchedHandler = self::normalizedHandler( $response->get_matched_handler() );
		$selected       = null === $matchedHandler ? null : ProtectedRoute::assignmentFor( $matchedHandler );
		if ( null === $selected ) {
			return rest_send_allow_header( $response, $server, $request );
		}

		try {
			$mode = $this->requestModes[ $request ] ?? self::MODE_REJECTED;
			if ( self::MODE_REJECTED === $mode ) {
				return $response;
			}

			$matchedRoute = $response->get_matched_route();
			$routes       = $server->get_routes();
			$handlers     = $routes[ $matchedRoute ] ?? null;
			if ( ! is_array( $handlers ) ) {
				return $response;
			}

			$allowedMethods = array();
			foreach ( $handlers as $rawHandler ) {
				$handler = self::normalizedHandler( $rawHandler );
				if ( null === $handler ) {
					continue;
				}

				$assignment = ProtectedRoute::assignmentFor( $handler );
				$allowed    = null === $assignment
					? $this->wordpressPermissionAllows( $handler, $request )
					: $this->protectedPermissionAllows( $handler, $assignment, $request, $mode );

				if ( ! $allowed || ! is_array( $handler['methods'] ?? null ) ) {
					continue;
				}

				foreach ( $handler['methods'] as $method => $enabled ) {
					if ( $enabled ) {
						$allowedMethods[ strtoupper( (string) $method ) ] = true;
					}
				}
			}

			if ( array() !== $allowedMethods ) {
				$response->header( 'Allow', implode( ', ', array_keys( $allowedMethods ) ) );
			}

			return $response;
		} finally {
			unset( $this->requestModes[ $request ] );
		}
	}

	/**
	 * Creates one owned WordPress error for short-circuiting callbacks.
	 *
	 * @since 0.1.0
	 *
	 * @param string        $code        Internal error identity.
	 * @param string|null   $oauthError  Challenge error parameter.
	 * @param string        $description Safe public description.
	 * @param int           $status      HTTP status.
	 * @param array<string> $scopes      Challenge scopes.
	 * @param string|null   $resourceMetadata Exact RFC 9728 metadata URL when challenge-safe.
	 */
	private function error( string $code, ?string $oauthError, string $description, int $status, array $scopes, ?string $resourceMetadata ): WP_Error {
		$error                  = new WP_Error( $code, $description, array( 'status' => $status ) );
		$this->errors[ $error ] = array(
			'error'             => $oauthError,
			'description'       => $description,
			'status'            => $status,
			'scopes'            => $scopes,
			'resource_metadata' => $resourceMetadata,
		);

		return $error;
	}

	/**
	 * Builds a Bearer challenge with an exact resource_metadata reference only.
	 *
	 * @since 0.1.0
	 *
	 * @param string|null   $error  Optional OAuth error.
	 * @param array<string> $scopes Exact required scopes.
	 * @param string|null   $resourceMetadata Exact RFC 9728 metadata URL.
	 */
	private static function challenge( ?string $error, array $scopes, ?string $resourceMetadata ): string {
		$parameters = array();
		if ( null !== $error ) {
			$parameters['error'] = $error;
		}
		if ( array() !== $scopes ) {
			$parameters['scope'] = implode( ' ', $scopes );
		}
		if ( null !== $resourceMetadata ) {
			$parameters['resource_metadata'] = $resourceMetadata;
		}

		$parts = array();
		foreach ( $parameters as $name => $value ) {
			$parts[] = $name . '="' . addcslashes( $value, '\\"' ) . '"';
		}

		return 'Bearer' . ( array() === $parts ? '' : ' ' . implode( ', ', $parts ) );
	}

	/**
	 * Returns challenge metadata only when the assigned audience is the exact
	 * public URL selected by this REST request.
	 *
	 * @param RouteAssignment $assignment Exact handler assignment.
	 * @param WP_REST_Request $request Matched request.
	 */
	private function resourceMetadata( RouteAssignment $assignment, WP_REST_Request $request ): ?string {
		$identity = $this->siteState->identity();
		if ( null === $identity ) {
			return null;
		}

		$resource = $assignment->resource( $identity->issuer() );
		if ( $identity->issuer() === $resource ) {
			return null;
		}
		$policy = $this->accessPolicy->forIssuer( $identity->issuer() );
		$urls   = new EndpointUrls( $identity->issuer() );
		if (
			! $policy->assignmentAvailable( $resource, $assignment->requiredScopes() )
			|| $resource !== $urls->restRoute( $request->get_route() )
		) {
			return null;
		}

		return $urls->protectedResourceMetadata( $resource );
	}

	/**
	 * Evaluates a protected handler under the identity allowed for this request.
	 *
	 * @since 0.1.0
	 *
	 * @param array<string, mixed> $handler    Registered REST handler.
	 * @param RouteAssignment      $assignment Exact OAuth assignment.
	 * @param WP_REST_Request      $request    Matched request.
	 * @param string               $mode       Earlier authentication result.
	 */
	private function protectedPermissionAllows( array $handler, RouteAssignment $assignment, WP_REST_Request $request, string $mode ): bool {
		if ( self::MODE_LEGACY === $mode ) {
			return $this->wordpressPermissionAllows( $handler, $request );
		}
		if ( self::MODE_BEARER !== $mode ) {
			return false;
		}

		$authorizationHeader = (string) $request->get_header( 'authorization' );
		if ( 1 !== preg_match( '/^Bearer ([A-Za-z0-9_-]{20,256})$/Di', $authorizationHeader, $matches ) ) {
			return false;
		}

		$identity = $this->siteState->identity();
		if ( null === $identity ) {
			return false;
		}

		try {
			$context = $this->tokens->validateAccessToken(
				$matches[1],
				$assignment->resource( $identity->issuer() ),
				$assignment->requiredScopes()
			);
		} catch ( ProtocolException ) {
			return false;
		}

		$priorUserId  = get_current_user_id();
		$priorContext = $this->currentContext;
		try {
			$this->currentContext = $context;
			wp_set_current_user( $context->userId() );

			return $this->wordpressPermissionAllows( $handler, $request );
		} finally {
			$this->currentContext = $priorContext;
			wp_set_current_user( $priorUserId );
		}
	}

	/**
	 * Applies one registered WordPress permission callback unchanged.
	 *
	 * @since 0.1.0
	 *
	 * @param array<string, mixed> $handler Registered REST handler.
	 * @param WP_REST_Request      $request Matched request.
	 */
	private function wordpressPermissionAllows( array $handler, WP_REST_Request $request ): bool {
		$permissionCallback = $handler['permission_callback'] ?? null;

		return ! is_callable( $permissionCallback ) || true === call_user_func( $permissionCallback, $request );
	}

	/**
	 * Removes one request's temporary WordPress identity frame.
	 *
	 * @since 0.1.0
	 *
	 * @param WP_REST_Request $request Matched request.
	 */
	private function cleanupRequest( WP_REST_Request $request ): void {
		if ( ! isset( $this->frames[ $request ] ) ) {
			return;
		}

		$frame = $this->frames[ $request ];
		unset( $this->frames[ $request ] );
		$this->currentContext = $frame['prior_context'];
		wp_set_current_user( $frame['prior_user_id'] );
	}

	/**
	 * Retains only the named fields of a WordPress REST handler.
	 *
	 * @since 0.1.0
	 *
	 * @param mixed $handler Raw handler value.
	 * @return array<string, mixed>|null Normalized handler or null.
	 */
	private static function normalizedHandler( mixed $handler ): ?array {
		if ( ! is_array( $handler ) ) {
			return null;
		}

		$normalized = array();
		foreach ( $handler as $key => $value ) {
			if ( is_string( $key ) ) {
				$normalized[ $key ] = $value;
			}
		}

		return $normalized;
	}
}
