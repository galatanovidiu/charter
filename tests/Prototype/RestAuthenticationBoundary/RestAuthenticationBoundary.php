<?php
/**
 * Disposable Slice 0 WordPress REST authentication boundary.
 *
 * @package GalatanOvidiu\Charter
 */

declare(strict_types=1);

namespace GalatanOvidiu\Charter\Tests\Prototype\RestAuthenticationBoundary;

use WP_Error;
use WP_REST_Request;
use WP_REST_Response;
use WP_REST_Server;

/** Composes matched-handler classification, validation, identity, and cleanup. @since 0.1.0 */
final class RestAuthenticationBoundary {
	private const MODE_BEARER   = 'bearer';
	private const MODE_LEGACY   = 'legacy';
	private const MODE_MIXED    = 'mixed';
	private const MODE_REJECTED = 'rejected';

	/**
	 * Whether proof hooks are installed.
	 *
	 * @var bool
	 */
	private bool $installed = false;

	/**
	 * Request outcomes retained only for a possible later Allow pass.
	 *
	 * @var \WeakMap<WP_REST_Request, string>
	 */
	private \WeakMap $requestModes;

	/**
	 * Original Core Allow-filter priority, or false when it was absent.
	 *
	 * @var int|false
	 */
	private int|false $coreAllowPriority = false;

	/**
	 * Creates the proof composition.
	 *
	 * @param SyntheticBearerValidator   $validator In-memory validator.
	 * @param RequestContextStack        $contexts Request-keyed contexts.
	 * @param InvocationLedger           $invocations Sanitized ledger.
	 * @param ChallengeResponseProjector $challenges Challenge projector.
	 */
	public function __construct(
		private readonly SyntheticBearerValidator $validator,
		private readonly RequestContextStack $contexts,
		private readonly InvocationLedger $invocations,
		private readonly ChallengeResponseProjector $challenges
	) {
		$this->requestModes = new \WeakMap();
	}

	/**
	 * Creates a complete boundary from process-local fixtures.
	 *
	 * @param SyntheticBearerFixtures $fixtures Process-local fixtures.
	 */
	public static function fromFixtures( SyntheticBearerFixtures $fixtures ): self {
		return new self( $fixtures->validator(), new RequestContextStack(), new InvocationLedger(), new ChallengeResponseProjector() );
	}

	/** Installs disposable proof hooks. */
	public function install(): void {
		if ( $this->installed ) {
			return; }
		add_filter( 'rest_request_before_callbacks', array( $this, 'beforeCallbacks' ), 10, 3 );
		add_filter( 'rest_request_after_callbacks', array( $this, 'afterCallbacks' ), 10, 3 );
		$this->coreAllowPriority = has_filter( 'rest_post_dispatch', 'rest_send_allow_header' );
		if ( is_int( $this->coreAllowPriority ) ) {
			remove_filter( 'rest_post_dispatch', 'rest_send_allow_header', $this->coreAllowPriority );
		}
		add_filter( 'rest_post_dispatch', array( $this, 'sendAllowHeader' ), 10, 3 );
		$this->installed = true;
	}

	/** Removes disposable proof hooks and restores identity. */
	public function remove(): void {
		if ( $this->installed ) {
			remove_filter( 'rest_request_before_callbacks', array( $this, 'beforeCallbacks' ), 10 );
			remove_filter( 'rest_request_after_callbacks', array( $this, 'afterCallbacks' ), 10 );
			remove_filter( 'rest_post_dispatch', array( $this, 'sendAllowHeader' ), 10 );
			if ( is_int( $this->coreAllowPriority ) ) {
				add_filter( 'rest_post_dispatch', 'rest_send_allow_header', $this->coreAllowPriority, 3 );
			}
		}
		$this->contexts->restoreAll();
		$this->requestModes      = new \WeakMap();
		$this->coreAllowPriority = false;
		$this->installed         = false;
	}

	/**
	 * Applies matched-handler authentication before permission callbacks.
	 *
	 * @param mixed                $response Current response.
	 * @param array<string, mixed> $handler Core-selected handler.
	 * @param WP_REST_Request      $request Matched request.
	 * @return mixed Filtered response.
	 */
	public function beforeCallbacks( mixed $response, array $handler, WP_REST_Request $request ): mixed {
		$assignment = ProtectedRouteRegistry::assignmentFor( $handler );
		if ( ! $assignment instanceof ProtectedRouteAssignment ) {
			return $response; }
		$hasBearerAttempt = $this->validator->hasBearerAttempt( $request );
		$isWordPressAuth  = get_current_user_id() > 0 && null === $this->contexts->current();

		if ( ! $hasBearerAttempt && $isWordPressAuth ) {
			$this->requestModes[ $request ] = self::MODE_LEGACY;
			$this->invocations->record( $request, $assignment->routeLabel(), 'legacy_auth_preserved', false, $this->contexts->depth(), BearerValidationDecision::NO_BEARER );
			return $response;
		}
		if ( ! $hasBearerAttempt ) {
			$this->requestModes[ $request ] = self::MODE_REJECTED;
			$this->invocations->record( $request, $assignment->routeLabel(), 'bearer_missing', false, $this->contexts->depth(), BearerValidationDecision::NO_BEARER );
			return $this->challenges->errorFor( BearerValidationDecision::NO_BEARER );
		}

		if ( $isWordPressAuth ) {
			$this->requestModes[ $request ] = self::MODE_MIXED;
			$this->invocations->record( $request, $assignment->routeLabel(), 'mixed_auth_rejected', false, $this->contexts->depth(), BearerValidationDecision::INVALID_REQUEST );
			return $this->challenges->mixedAuthenticationError();
		}
		$decision = $this->validator->validate( $request, $assignment );
		if ( BearerValidationDecision::VALID !== $decision->outcome() ) {
			$this->requestModes[ $request ] = self::MODE_REJECTED;
			$this->invocations->record( $request, $assignment->routeLabel(), 'bearer_rejected', false, $this->contexts->depth(), $decision->outcome() );
			return $this->challenges->errorFor( $decision->outcome() );
		}
		$result = $decision->result();
		if ( ! $result instanceof BearerValidationResult ) {
			$this->requestModes[ $request ] = self::MODE_REJECTED;
			return $this->challenges->errorFor( BearerValidationDecision::INVALID_TOKEN ); }
		$this->requestModes[ $request ] = self::MODE_BEARER;
		$this->contexts->enter( $request, $result );
		$this->invocations->record( $request, $assignment->routeLabel(), 'bearer_context_entered', true, $this->contexts->depth(), $decision->outcome() );
		return $response;
	}

	/**
	 * Restores request identity and projects proof-owned errors.
	 *
	 * @param mixed                $response Current response.
	 * @param array<string, mixed> $handler Core-selected handler.
	 * @param WP_REST_Request      $request Matched request.
	 * @return mixed Filtered response.
	 */
	public function afterCallbacks( mixed $response, array $handler, WP_REST_Request $request ): mixed {
		$assignment = ProtectedRouteRegistry::assignmentFor( $handler );
		if ( ! $assignment instanceof ProtectedRouteAssignment ) {
			return $response; }
		if ( $this->contexts->hasFor( $request ) ) {
			$this->contexts->leave( $request );
			$this->invocations->record( $request, $assignment->routeLabel(), 'bearer_context_restored', false, $this->contexts->depth() );
		}
		return $response instanceof WP_Error && $this->challenges->isProofError( $response ) ? $this->challenges->project( $response, $assignment ) : $response;
	}

	/**
	 * Builds Core-compatible Allow output while preserving per-handler OAuth gates.
	 *
	 * @param WP_REST_Response $response Current response.
	 * @param WP_REST_Server   $server REST server.
	 * @param WP_REST_Request  $request Matched request.
	 */
	public function sendAllowHeader( WP_REST_Response $response, WP_REST_Server $server, WP_REST_Request $request ): WP_REST_Response {
		$matchedRoute   = $response->get_matched_route();
		$matchedHandler = $response->get_matched_handler();
		$routes         = $server->get_routes();
		$handlers       = is_string( $matchedRoute ) ? ( $routes[ $matchedRoute ] ?? null ) : null;

		$selectedAssignment = is_array( $matchedHandler ) ? ProtectedRouteRegistry::assignmentFor( $matchedHandler ) : null;
		if ( ! is_array( $handlers ) || ! $selectedAssignment instanceof ProtectedRouteAssignment ) {
			return rest_send_allow_header( $response, $server, $request );
		}

		$allowedMethods = array();
		$mode           = $this->requestModes[ $request ] ?? self::MODE_REJECTED;
		$depth          = $this->contexts->depth();

		try {
			foreach ( $handlers as $handler ) {
				if ( ! is_array( $handler ) ) {
					continue;
				}

				$assignment = ProtectedRouteRegistry::assignmentFor( $handler );
				$methods    = is_array( $handler['methods'] ?? null ) ? $handler['methods'] : array();
				foreach ( $methods as $method => $enabled ) {
					if ( ! $enabled ) {
						continue;
					}

					$allowed                            = $assignment instanceof ProtectedRouteAssignment
						? $this->protectedHandlerAllows( $handler, $assignment, $request, $mode )
						: ( in_array( $mode, array( self::MODE_BEARER, self::MODE_LEGACY ), true ) && $this->wordpressHandlerAllows( $handler, $request ) );
					$allowedMethods[ (string) $method ] = $allowed;
				}
			}

			$allowedMethods = array_filter( $allowedMethods );
			if ( array() !== $allowedMethods ) {
				$response->header( 'Allow', implode( ', ', array_map( 'strtoupper', array_keys( $allowedMethods ) ) ) );
			}

			return $response;
		} finally {
			unset( $this->requestModes[ $request ] );
			$this->contexts->restoreToDepth( $depth );
		}
	}

	/**
	 * Dispatches with bounded throwable cleanup.
	 *
	 * @param WP_REST_Server  $server REST server.
	 * @param WP_REST_Request $request Request to dispatch.
	 */
	public function dispatchExceptionSafely( WP_REST_Server $server, WP_REST_Request $request ): WP_REST_Response {
		$depth = $this->contexts->depth();
		try {
			return $server->dispatch( $request );
		} finally {
			$this->contexts->restoreToDepth( $depth ); }
	}

	/**
	 * Records one callback-owned invocation.
	 *
	 * @param WP_REST_Request $request Request under test.
	 * @param string          $routeLabel Fixed handler label.
	 * @param string          $phase Fixed callback phase.
	 * @param string|null     $outcome Optional result.
	 */
	public function recordInvocation( WP_REST_Request $request, string $routeLabel, string $phase, ?string $outcome = null ): void {
		$this->invocations->record( $request, $routeLabel, $phase, null !== $this->contexts->current(), $this->contexts->depth(), $outcome );
	}

	/** Resets proof state without changing fixtures. */
	public function reset(): void {
		$this->contexts->restoreAll();
		$this->requestModes = new \WeakMap();
		$this->invocations->reset();
		$this->validator->resetValidationCount();
		$this->challenges->reset(); }
	/** Returns the synthetic validator. */
	public function validator(): SyntheticBearerValidator {
		return $this->validator; }
	/** Returns the request context stack. */
	public function contexts(): RequestContextStack {
		return $this->contexts; }
	/** Returns the sanitized invocation ledger. */
	public function invocations(): InvocationLedger {
		return $this->invocations; }
	/** Returns the challenge projector. */
	public function challenges(): ChallengeResponseProjector {
		return $this->challenges; }

	/**
	 * Evaluates one protected alternate method only after its own OAuth gate.
	 *
	 * @param array<string, mixed>     $handler Exact registered handler.
	 * @param ProtectedRouteAssignment $assignment Exact handler assignment.
	 * @param WP_REST_Request          $request Original request.
	 * @param string                   $mode Authentication outcome from the selected handler.
	 */
	private function protectedHandlerAllows( array $handler, ProtectedRouteAssignment $assignment, WP_REST_Request $request, string $mode ): bool {
		if ( self::MODE_LEGACY === $mode ) {
			return $this->wordpressHandlerAllows( $handler, $request );
		}

		if ( self::MODE_BEARER !== $mode ) {
			return false;
		}

		$decision = $this->validator->validate( $request, $assignment );
		if ( BearerValidationDecision::VALID !== $decision->outcome() || ! $decision->result() instanceof BearerValidationResult ) {
			$this->invocations->record( $request, $assignment->routeLabel(), 'allow_bearer_rejected', false, $this->contexts->depth(), $decision->outcome() );
			return false;
		}

		$depth = $this->contexts->depth();
		$this->contexts->enter( $request, $decision->result() );
		$this->invocations->record( $request, $assignment->routeLabel(), 'allow_context_entered', true, $this->contexts->depth(), $decision->outcome() );
		try {
			return $this->wordpressHandlerAllows( $handler, $request );
		} finally {
			$this->contexts->restoreToDepth( $depth );
		}
	}

	/**
	 * Applies one unchanged WordPress permission callback.
	 *
	 * @param array<string, mixed> $handler Exact registered handler.
	 * @param WP_REST_Request      $request Original request.
	 */
	private function wordpressHandlerAllows( array $handler, WP_REST_Request $request ): bool {
		$permissionCallback = $handler['permission_callback'] ?? null;

		return ! is_callable( $permissionCallback ) || true === call_user_func( $permissionCallback, $request );
	}
}
