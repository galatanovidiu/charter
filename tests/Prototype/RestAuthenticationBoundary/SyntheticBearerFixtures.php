<?php
/**
 * Disposable Slice 0 process-local Bearer fixtures.
 *
 * @package GalatanOvidiu\Charter
 */

declare(strict_types=1);

namespace GalatanOvidiu\Charter\Tests\Prototype\RestAuthenticationBoundary;

use InvalidArgumentException;
use WP_REST_Request;

/** Generates random bearer values held only inside one proof process. @since 0.1.0 */
final class SyntheticBearerFixtures {
	public const DEFAULT_ISSUER          = 'https://charter.example.test';
	public const DEFAULT_RESOURCE        = self::DEFAULT_ISSUER;
	public const ISOLATED_RESOURCE       = self::DEFAULT_ISSUER . '/isolated';
	public const GENERAL_SCOPE           = 'wordpress:access';
	public const CASE_VALID_A_DEFAULT    = 'valid_a_default';
	public const CASE_VALID_B_DEFAULT    = 'valid_b_default';
	public const CASE_VALID_A_ISOLATED   = 'valid_a_isolated';
	public const CASE_INSUFFICIENT_SCOPE = 'insufficient_scope';
	public const CASE_EXPIRED            = 'expired';
	public const CASE_REVOKED            = 'revoked';
	public const CASE_UNKNOWN            = 'unknown';
	public const CASE_WRONG_ISSUER       = 'wrong_issuer';
	public const CASE_WRONG_RESOURCE     = 'wrong_resource';
	public const CASE_WRONG_CLIENT       = 'wrong_client';
	public const CASE_WRONG_USER         = 'wrong_user';
	public const CASE_WRONG_GRANT        = 'wrong_grant';
	public const CASE_POLICY_DENIED      = 'policy_denied';
	public const CASE_MALFORMED          = 'malformed';
	/**
	 * Random bearer values keyed by semantic case.
	 *
	 * @var array<string, string>
	 */
	private array $credentials = array();
	/**
	 * Validator sharing the same process-local values.
	 *
	 * @var SyntheticBearerValidator
	 */
	private readonly SyntheticBearerValidator $validator;

	/**
	 * Creates the complete semantic fixture matrix.
	 *
	 * @param int                   $userAId First represented WordPress user.
	 * @param int                   $userBId Second represented WordPress user.
	 * @param array<string, string> $credentialOverrides Optional exact process-local credentials.
	 * @throws InvalidArgumentException When a user ID or credential override is invalid.
	 */
	public function __construct( int $userAId, int $userBId, array $credentialOverrides = array() ) {
		if ( $userAId < 1 || $userBId < 1 ) {
			throw new InvalidArgumentException( 'rest_auth_boundary_user_invalid' ); }
		$cases = array( self::CASE_VALID_A_DEFAULT, self::CASE_VALID_B_DEFAULT, self::CASE_VALID_A_ISOLATED, self::CASE_INSUFFICIENT_SCOPE, self::CASE_EXPIRED, self::CASE_REVOKED, self::CASE_UNKNOWN, self::CASE_WRONG_ISSUER, self::CASE_WRONG_RESOURCE, self::CASE_WRONG_CLIENT, self::CASE_WRONG_USER, self::CASE_WRONG_GRANT, self::CASE_POLICY_DENIED, self::CASE_MALFORMED );
		foreach ( $credentialOverrides as $caseName => $credential ) {
			if ( ! in_array( $caseName, $cases, true ) || 1 !== preg_match( '/^[a-f0-9]{64}$/D', $credential ) ) {
				throw new InvalidArgumentException( 'rest_auth_boundary_credential_override_invalid' );
			}
		}
		foreach ( $cases as $caseName ) {
			$this->credentials[ $caseName ] = $credentialOverrides[ $caseName ] ?? bin2hex( random_bytes( 32 ) ); }
		$records         = array(
			$this->credential( self::CASE_VALID_A_DEFAULT ) => self::record( $userAId ),
			$this->credential( self::CASE_VALID_B_DEFAULT ) => self::record( $userBId ),
			$this->credential( self::CASE_VALID_A_ISOLATED ) => self::record( $userAId, self::DEFAULT_ISSUER, self::ISOLATED_RESOURCE ),
			$this->credential( self::CASE_INSUFFICIENT_SCOPE ) => self::record( $userAId, self::DEFAULT_ISSUER, self::DEFAULT_RESOURCE, array( 'charter-proof:other' ) ),
			$this->credential( self::CASE_EXPIRED )        => self::invalidRecord( $userAId, 0 ),
			$this->credential( self::CASE_REVOKED )        => self::invalidRecord( $userAId, 0 ),
			$this->credential( self::CASE_WRONG_ISSUER )   => self::record( $userAId, 'https://wrong.example.test' ),
			$this->credential( self::CASE_WRONG_RESOURCE ) => self::record( $userAId, self::DEFAULT_ISSUER, self::ISOLATED_RESOURCE ),
			$this->credential( self::CASE_WRONG_CLIENT )   => new SyntheticBearerRecord( self::DEFAULT_ISSUER, self::DEFAULT_RESOURCE, 'wrong-client', $userAId, array( self::GENERAL_SCOPE ) ),
			$this->credential( self::CASE_WRONG_USER )     => self::invalidRecord( $userAId, 2 ),
			$this->credential( self::CASE_WRONG_GRANT )    => self::invalidRecord( $userAId, 3 ),
			$this->credential( self::CASE_POLICY_DENIED )  => self::invalidRecord( $userAId, 4 ),
		);
		$this->validator = new SyntheticBearerValidator( $records );
	}

	/**
	 * Applies one credential directly to a request.
	 *
	 * @param WP_REST_Request $request Request under test.
	 * @param string          $caseName Semantic fixture case.
	 */
	public function authorize( WP_REST_Request $request, string $caseName ): void {
		$request->set_header( 'Authorization', $this->authorizationHeader( $caseName ) ); }
	/**
	 * Returns one process-local Authorization value.
	 *
	 * @param string $caseName Semantic fixture case.
	 * @return string Authorization header value.
	 */
	public function authorizationHeader( string $caseName ): string {
		return 'Bearer ' . $this->credential( $caseName ); }
	/** Returns the validator sharing these values. */
	public function validator(): SyntheticBearerValidator {
		return $this->validator; }
	/**
	 * Reads one in-memory credential.
	 *
	 * @param string $caseName Semantic fixture case.
	 * @return string Opaque credential.
	 * @throws InvalidArgumentException For an unknown case.
	 */
	private function credential( string $caseName ): string {
		$value = $this->credentials[ $caseName ] ?? null;
		if ( ! is_string( $value ) ) {
			throw new InvalidArgumentException( 'rest_auth_boundary_case_unknown' ); }
		return $value;
	}

	/**
	 * Creates one current synthetic record.
	 *
	 * @param int           $userId Represented WordPress user.
	 * @param string        $issuer Exact bound issuer.
	 * @param string        $resourceIdentifier Exact bound resource.
	 * @param array<string> $scopes Bound OAuth scopes.
	 */
	private static function record( int $userId, string $issuer = self::DEFAULT_ISSUER, string $resourceIdentifier = self::DEFAULT_RESOURCE, array $scopes = array( self::GENERAL_SCOPE ) ): SyntheticBearerRecord {
		return new SyntheticBearerRecord( $issuer, $resourceIdentifier, 'charter-slice0-client', $userId, $scopes );
	}

	/**
	 * Creates one record with a failed current-state check.
	 *
	 * @param int $userId Represented WordPress user.
	 * @param int $position Failed state position.
	 */
	private static function invalidRecord( int $userId, int $position ): SyntheticBearerRecord {
		$states              = array( true, true, true, true, true );
		$states[ $position ] = false;

		return new SyntheticBearerRecord( self::DEFAULT_ISSUER, self::DEFAULT_RESOURCE, 'charter-slice0-client', $userId, array( self::GENERAL_SCOPE ), ...$states );
	}
}
