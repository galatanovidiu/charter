<?php
/**
 * Dynamic Client Registration metadata validation.
 *
 * @package GalatanOvidiu\Charter
 */

declare(strict_types=1);

namespace GalatanOvidiu\Charter\OAuth;

use InvalidArgumentException;
use JsonException;
use stdClass;

/**
 * Validates a bounded RFC 7591 subset without applying unsafe legacy defaults.
 *
 * @since 0.1.0
 */
final class DynamicRegistrationValidator {

	private const MAX_BODY_BYTES   = 16384;
	private const MAX_DEPTH        = 16;
	private const MAX_NODES        = 256;
	private const MAX_ROOT_MEMBERS = 64;
	private const MAX_STRING_BYTES = 2048;
	private const MAX_REDIRECTS    = 32;

	private const FORBIDDEN_MEMBERS = array(
		'client_id',
		'client_secret',
		'client_secret_expires_at',
		'jwks',
		'jwks_uri',
		'registration_access_token',
		'registration_client_uri',
		'signed_jwks_uri',
		'software_statement',
		'token_endpoint_auth_signing_alg',
	);

	/**
	 * Validates one complete JSON request body.
	 *
	 * @param string $body Complete JSON body.
	 * @throws InvalidArgumentException When metadata is malformed or unsupported.
	 */
	public static function validate( string $body ): DynamicRegistrationRequest {
		if ( '' === $body || self::MAX_BODY_BYTES < strlen( $body ) ) {
			throw new InvalidArgumentException( 'charter_dcr_metadata_invalid' );
		}

		self::rejectDuplicateRootMembers( $body );
		try {
			$decoded = json_decode( $body, false, 64, JSON_THROW_ON_ERROR );
		} catch ( JsonException ) {
			throw new InvalidArgumentException( 'charter_dcr_metadata_invalid' );
		}

		$nodes = 0;
		if ( ! $decoded instanceof stdClass || self::MAX_ROOT_MEMBERS < count( get_object_vars( $decoded ) ) || ! self::hasBoundedStructure( $decoded, 1, $nodes ) ) {
			throw new InvalidArgumentException( 'charter_dcr_metadata_invalid' );
		}
		$metadata = get_object_vars( $decoded );
		foreach ( self::FORBIDDEN_MEMBERS as $member ) {
			if ( array_key_exists( $member, $metadata ) ) {
				throw new InvalidArgumentException( 'charter_dcr_metadata_invalid' );
			}
		}

		$name       = $metadata['client_name'] ?? null;
		$redirects  = $metadata['redirect_uris'] ?? null;
		$method     = $metadata['token_endpoint_auth_method'] ?? null;
		$grantTypes = $metadata['grant_types'] ?? array( Client::GRANT_AUTHORIZATION_CODE );
		$responses  = $metadata['response_types'] ?? array( 'code' );
		$grantTypes = self::grantTypes( $grantTypes );
		if (
			! is_string( $name )
			|| '' === trim( $name )
			|| 256 < strlen( $name )
			|| ! is_array( $redirects )
			|| ! array_is_list( $redirects )
			|| array() === $redirects
			|| self::MAX_REDIRECTS < count( $redirects )
			|| ! is_string( $method )
			|| ! in_array( $method, array( Client::AUTH_NONE, Client::AUTH_CLIENT_SECRET_POST ), true )
			|| ! self::isExactStringSet( $responses, array( 'code' ) )
			|| null === $grantTypes
		) {
			throw new InvalidArgumentException( 'charter_dcr_metadata_invalid' );
		}

		$unique = array();
		foreach ( $redirects as $redirect ) {
			if ( ! is_string( $redirect ) || isset( $unique[ $redirect ] ) || ! RedirectUriValidator::isValid( $redirect ) ) {
				throw new InvalidArgumentException( 'charter_dcr_redirect_invalid' );
			}
			$unique[ $redirect ] = true;
		}

		return new DynamicRegistrationRequest(
			trim( $name ),
			array_keys( $unique ),
			$method,
			in_array( Client::GRANT_REFRESH_TOKEN, $grantTypes, true )
		);
	}

	/**
	 * Validates the supported grant set.
	 *
	 * @param mixed $grantTypes Candidate grant types.
	 * @return list<string>|null Validated grant types.
	 */
	private static function grantTypes( mixed $grantTypes ): ?array {
		if ( ! is_array( $grantTypes ) || ! array_is_list( $grantTypes ) ) {
			return null;
		}

		$validated = array();
		foreach ( $grantTypes as $grantType ) {
			if ( ! is_string( $grantType ) || ! in_array( $grantType, array( Client::GRANT_AUTHORIZATION_CODE, Client::GRANT_REFRESH_TOKEN ), true ) ) {
				return null;
			}
			$validated[] = $grantType;
		}

		return in_array( Client::GRANT_AUTHORIZATION_CODE, $validated, true ) && count( $validated ) === count( array_unique( $validated ) )
			? $validated
			: null;
	}

	/**
	 * Checks one exact ordered string set.
	 *
	 * @param mixed         $actual Candidate list.
	 * @param array<string> $expected Expected list.
	 */
	private static function isExactStringSet( mixed $actual, array $expected ): bool {
		return is_array( $actual ) && array_is_list( $actual ) && $actual === $expected;
	}

	/**
	 * Enforces aggregate JSON depth and node bounds.
	 *
	 * @param mixed $value Current value.
	 * @param int   $depth Current depth.
	 * @param int   $nodes Aggregate node count.
	 */
	private static function hasBoundedStructure( mixed $value, int $depth, int &$nodes ): bool {
		if ( self::MAX_DEPTH < $depth || self::MAX_NODES < ++$nodes ) {
			return false;
		}
		if ( is_string( $value ) ) {
			return strlen( $value ) <= self::MAX_STRING_BYTES;
		}
		if ( $value instanceof stdClass ) {
			foreach ( get_object_vars( $value ) as $name => $member ) {
				if ( 128 < strlen( $name ) || ! self::hasBoundedStructure( $member, $depth + 1, $nodes ) ) {
					return false;
				}
			}
		}
		if ( is_array( $value ) ) {
			foreach ( $value as $member ) {
				if ( ! self::hasBoundedStructure( $member, $depth + 1, $nodes ) ) {
					return false;
				}
			}
		}

		return true;
	}

	/**
	 * Rejects duplicate root names before JSON projection can hide them.
	 *
	 * @param string $body Raw JSON body.
	 * @throws InvalidArgumentException When a member repeats.
	 */
	private static function rejectDuplicateRootMembers( string $body ): void {
		$length      = strlen( $body );
		$depth       = 0;
		$expectKey   = false;
		$inString    = false;
		$escaped     = false;
		$stringStart = null;
		$seen        = array();

		for ( $offset = 0; $offset < $length; ++$offset ) {
			$character = $body[ $offset ];
			if ( $inString ) {
				if ( $escaped ) {
					$escaped = false;
					continue;
				}
				if ( '\\' === $character ) {
					$escaped = true;
					continue;
				}
				if ( '"' !== $character ) {
					continue;
				}
				$inString = false;
				if ( 1 === $depth && $expectKey && is_int( $stringStart ) ) {
					$name = json_decode( substr( $body, $stringStart, $offset - $stringStart + 1 ), true );
					if ( ! is_string( $name ) || isset( $seen[ $name ] ) ) {
						throw new InvalidArgumentException( 'charter_dcr_metadata_invalid' );
					}
					$seen[ $name ] = true;
					$expectKey     = false;
				}
				continue;
			}

			if ( '"' === $character ) {
				$inString    = true;
				$stringStart = $offset;
			} elseif ( '{' === $character || '[' === $character ) {
				++$depth;
				$expectKey = 1 === $depth && '{' === $character;
			} elseif ( '}' === $character || ']' === $character ) {
				--$depth;
			} elseif ( 1 === $depth && ',' === $character ) {
				$expectKey = true;
			}
		}
	}

	/** This class contains static validation only. */
	private function __construct() {
	}
}
