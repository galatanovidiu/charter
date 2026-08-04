<?php
/**
 * Disposable Slice 0 in-memory Bearer validator.
 *
 * @package GalatanOvidiu\Charter
 */

declare(strict_types=1);

namespace GalatanOvidiu\Charter\Tests\Prototype\RestAuthenticationBoundary;

use WP_REST_Request;
use WP_User;

/** Proves transport and validation ordering without production persistence. @since 0.1.0 */
final class SyntheticBearerValidator {
	private const EXPECTED_CLIENT = 'charter-slice0-client';
	/**
	 * Process-local credential lookup.
	 *
	 * @var array<string, SyntheticBearerRecord>
	 */
	private array $records;
	/**
	 * Number of semantic validation calls.
	 *
	 * @var int
	 */
	private int $validationCount = 0;
	/**
	 * Creates one in-memory validator.
	 *
	 * @param array<string, SyntheticBearerRecord> $records Credential-keyed records.
	 */
	public function __construct( array $records ) {
		$this->records = $records; }

	/**
	 * Reports whether any Bearer transport is attempted.
	 *
	 * @param WP_REST_Request $request Request under test.
	 */
	public function hasBearerAttempt( WP_REST_Request $request ): bool {
		foreach ( $request->get_header_as_array( 'Authorization' ) ?? array() as $value ) {
			if ( is_string( $value ) && 1 === preg_match( '/^\s*Bearer(?:\s|$)/i', $value ) ) {
				return true; }
		}
		return self::hasAlternateTransport( $request );
	}

	/**
	 * Validates one Bearer-only attempt.
	 *
	 * @param WP_REST_Request          $request Matched request.
	 * @param ProtectedRouteAssignment $assignment Exact handler assignment.
	 */
	public function validate( WP_REST_Request $request, ProtectedRouteAssignment $assignment ): BearerValidationDecision {
		++$this->validationCount;
		$values = array();
		foreach ( $request->get_header_as_array( 'Authorization' ) ?? array() as $value ) {
			if ( is_string( $value ) && 1 === preg_match( '/^\s*Bearer(?:\s|$)/i', $value ) ) {
				$values[] = $value;
			}
		}
		$alternate = self::hasAlternateTransport( $request );
		if ( count( $values ) > 1 || ( array() !== $values && $alternate ) ) {
			return BearerValidationDecision::invalidRequest(); }
		if ( array() === $values ) {
			return $alternate ? BearerValidationDecision::invalidRequest() : BearerValidationDecision::noBearer(); }
		if ( 1 !== preg_match( '/^Bearer[ \t]+([A-Za-z0-9\-._~+\/]+=*)$/iD', trim( $values[0] ), $matches ) ) {
			return BearerValidationDecision::invalidRequest(); }
		$record = $this->records[ $matches[1] ] ?? null;
		if ( ! $record instanceof SyntheticBearerRecord || ! $record->isCurrent() || $record->issuer() !== $assignment->issuer() || $record->resource() !== $assignment->resource() || self::EXPECTED_CLIENT !== $record->clientId() || ! get_userdata( $record->userId() ) instanceof WP_User ) {
			return BearerValidationDecision::invalidToken();
		}
		if ( array() !== array_diff( $assignment->requiredScopes(), $record->scopes() ) ) {
			return BearerValidationDecision::insufficientScope(); }
		return BearerValidationDecision::valid( new BearerValidationResult( $record->userId(), $record->resource(), $record->scopes() ) );
	}

	/** Returns the semantic validation-call count. */
	public function validationCount(): int {
		return $this->validationCount; }
	/** Clears the semantic validation-call count. */
	public function resetValidationCount(): void {
		$this->validationCount = 0; }

	/**
	 * Detects forbidden alternate access-token transport.
	 *
	 * @param WP_REST_Request $request Request under test.
	 */
	private static function hasAlternateTransport( WP_REST_Request $request ): bool {
		$jsonParameters = $request->get_json_params();

		return array_key_exists( 'access_token', $request->get_query_params() )
			|| array_key_exists( 'access_token', $request->get_body_params() )
			|| self::containsAccessToken( $jsonParameters )
			|| null !== $request->get_header( 'X-Charter-Access-Token' );
	}

	/**
	 * Safely checks a possibly absent parameter map.
	 *
	 * @param mixed $parameters Candidate parameter map.
	 */
	private static function containsAccessToken( mixed $parameters ): bool {
		return is_array( $parameters ) && array_key_exists( 'access_token', $parameters );
	}
}
