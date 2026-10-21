<?php
/**
 * Disposable Slice 0 OAuth challenge projector.
 *
 * @package GalatanOvidiu\Charter
 */

declare(strict_types=1);

namespace GalatanOvidiu\Charter\Tests\Prototype\RestAuthenticationBoundary;

use SplObjectStorage;
use WP_Error;
use WP_REST_Response;

/** Converts only proof-owned errors into exact Bearer response contracts. @since 0.1.0 */
final class ChallengeResponseProjector {
	public const MISSING_CODE = 'rest_not_logged_in';
	/**
	 * Proof-owned error identities.
	 *
	 * @var SplObjectStorage<WP_Error, null>
	 */
	private SplObjectStorage $proofErrors;

	/** Creates an empty proof-error registry. */
	public function __construct() {
		$this->proofErrors = new SplObjectStorage(); }

	/**
	 * Creates one generic protocol error.
	 *
	 * @param string $outcome Protocol outcome.
	 * @return WP_Error Proof-owned error.
	 */
	public function errorFor( string $outcome ): WP_Error {
		$error = match ( $outcome ) {
			BearerValidationDecision::INVALID_REQUEST => new WP_Error( 'invalid_request', 'The request uses invalid Bearer transport.', array( 'status' => 400 ) ),
			BearerValidationDecision::INVALID_TOKEN => new WP_Error( 'invalid_token', 'The access token is invalid.', array( 'status' => 401 ) ),
			BearerValidationDecision::INSUFFICIENT_SCOPE => new WP_Error( 'insufficient_scope', 'The access token has insufficient scope.', array( 'status' => 403 ) ),
			default => new WP_Error( self::MISSING_CODE, 'Authentication is required.', array( 'status' => 401 ) ),
		};
		$this->proofErrors->attach( $error );
		return $error;
	}

	/**
	 * Creates the approved mixed-authentication rejection.
	 *
	 * @return WP_Error Proof-owned generic error.
	 */
	public function mixedAuthenticationError(): WP_Error {
		$error = new WP_Error(
			'invalid_request',
			'Use either WordPress authentication or Bearer authentication, not both.',
			array( 'status' => 400 )
		);
		$this->proofErrors->attach( $error );

		return $error;
	}

	/**
	 * Projects the exact Bearer challenge.
	 *
	 * @param WP_Error                 $error Proof-owned error.
	 * @param ProtectedRouteAssignment $assignment Matched assignment.
	 * @return WP_REST_Response Projected response.
	 */
	public function project( WP_Error $error, ProtectedRouteAssignment $assignment ): WP_REST_Response {
		$response   = rest_convert_error_to_response( $error );
		$code       = $error->get_error_code();
		$parameters = array( 'resource_metadata' => $assignment->resourceMetadataUri() );
		if ( self::MISSING_CODE === $code || 'insufficient_scope' === $code ) {
			$parameters['scope'] = implode( ' ', $assignment->requiredScopes() ); }
		if ( self::MISSING_CODE !== $code ) {
			$parameters = array( 'error' => $code ) + $parameters; }
		$parts = array();
		foreach ( $parameters as $name => $value ) {
			if ( ! is_string( $value ) ) {
				continue;
			}
			$parts[] = $name . '="' . addcslashes( $value, '\\"' ) . '"'; }
		$response->header( 'WWW-Authenticate', 'Bearer ' . implode( ', ', $parts ) );
		$this->proofErrors->offsetUnset( $error );
		return $response;
	}

	/**
	 * Reports whether an error belongs to this projector.
	 *
	 * @param WP_Error $error Candidate error.
	 * @return bool Whether proof-owned.
	 */
	public function isProofError( WP_Error $error ): bool {
		return $this->proofErrors->offsetExists( $error );
	}

	/** Clears all unprojected proof errors. */
	public function reset(): void {
		$this->proofErrors = new SplObjectStorage(); }
}
