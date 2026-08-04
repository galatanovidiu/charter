<?php
/**
 * Disposable Slice 0 Bearer validation decision.
 *
 * @package GalatanOvidiu\Charter
 */

declare(strict_types=1);

namespace GalatanOvidiu\Charter\Tests\Prototype\RestAuthenticationBoundary;

/** Exposes only protocol outcomes and sanitized successful context. @since 0.1.0 */
final class BearerValidationDecision {
	public const NO_BEARER          = 'no_bearer';
	public const INVALID_REQUEST    = 'invalid_request';
	public const INVALID_TOKEN      = 'invalid_token';
	public const INSUFFICIENT_SCOPE = 'insufficient_scope';
	public const VALID              = 'valid';

	/**
	 * Creates one fixed decision.
	 *
	 * @param string                      $outcome Fixed protocol outcome.
	 * @param BearerValidationResult|null $result Sanitized successful result.
	 */
	private function __construct( private readonly string $outcome, private readonly ?BearerValidationResult $result = null ) {
	}

	/** Returns a missing-Bearer decision. */
	public static function noBearer(): self {
		return new self( self::NO_BEARER ); }
	/** Returns a malformed-transport decision. */
	public static function invalidRequest(): self {
		return new self( self::INVALID_REQUEST ); }
	/** Returns an invalid-credential decision. */
	public static function invalidToken(): self {
		return new self( self::INVALID_TOKEN ); }
	/** Returns an inadequate-scope decision. */
	public static function insufficientScope(): self {
		return new self( self::INSUFFICIENT_SCOPE ); }
	/**
	 * Returns a successful decision.
	 *
	 * @param BearerValidationResult $result Sanitized successful result.
	 */
	public static function valid( BearerValidationResult $result ): self {
		return new self( self::VALID, $result ); }
	/** Returns the protocol-level outcome. */
	public function outcome(): string {
		return $this->outcome; }
	/** Returns sanitized context only after success. */
	public function result(): ?BearerValidationResult {
		return $this->result; }
}
