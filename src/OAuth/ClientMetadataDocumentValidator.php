<?php
/**
 * Bounded Client ID Metadata Document validation.
 *
 * @package GalatanOvidiu\Charter
 */

declare(strict_types=1);

namespace GalatanOvidiu\Charter\OAuth;

use InvalidArgumentException;
use JsonException;
use stdClass;

/** Accepts only Charter's public-client CIMD profile. */
final class ClientMetadataDocumentValidator {

	private const SECURITY_MEMBERS = array(
		'client_id',
		'client_name',
		'redirect_uris',
		'token_endpoint_auth_method',
		'grant_types',
		'response_types',
		'client_secret',
		'client_secret_expires_at',
		'jwks',
		'jwks_uri',
	);

	private const FORBIDDEN_MEMBERS = array(
		'client_secret',
		'client_secret_expires_at',
		'registration_access_token',
		'registration_client_uri',
		'software_statement',
		'token_endpoint_auth_signing_alg',
	);

	/**
	 * Validates one complete identity-coded response body.
	 *
	 * @param string                   $body Complete bounded JSON body.
	 * @param ClientMetadataIdentifier $identifier Exact submitted identity.
	 * @throws InvalidArgumentException When the document is not authoritative.
	 */
	public static function validate( string $body, ClientMetadataIdentifier $identifier ): RemoteClientMetadata {
		if ( '' === $body || 5120 < strlen( $body ) ) {
			throw new InvalidArgumentException( 'charter_cimd_metadata_invalid' );
		}

		self::rejectDuplicateSecurityMembers( $body );
		try {
			$decoded = json_decode( $body, false, 64, JSON_THROW_ON_ERROR );
		} catch ( JsonException ) {
			throw new InvalidArgumentException( 'charter_cimd_metadata_invalid' );
		}

		$nodes = 0;
		if ( ! $decoded instanceof stdClass || 64 < count( get_object_vars( $decoded ) ) || ! self::hasBoundedStructure( $decoded, 1, $nodes ) ) {
			throw new InvalidArgumentException( 'charter_cimd_metadata_invalid' );
		}
		$document = get_object_vars( $decoded );
		foreach ( self::FORBIDDEN_MEMBERS as $member ) {
			if ( array_key_exists( $member, $document ) ) {
				throw new InvalidArgumentException( 'charter_cimd_metadata_invalid' );
			}
		}
		if ( self::containsPrivateKeyMaterial( $document['jwks'] ?? null ) ) {
			throw new InvalidArgumentException( 'charter_cimd_metadata_invalid' );
		}

		$clientId   = $document['client_id'] ?? null;
		$name       = $document['client_name'] ?? null;
		$safeName   = is_string( $name ) ? ClientDisplayName::normalize( $name ) : null;
		$redirects  = $document['redirect_uris'] ?? null;
		$method     = $document['token_endpoint_auth_method'] ?? null;
		$grantTypes = self::grantTypes( $document['grant_types'] ?? array( Client::GRANT_AUTHORIZATION_CODE ) );
		$responses  = $document['response_types'] ?? array( 'code' );
		if (
			! is_string( $clientId )
			|| $identifier->exact() !== $clientId
			|| ! is_string( $name )
			|| null === $safeName
			|| ! is_array( $redirects )
			|| ! array_is_list( $redirects )
			|| array() === $redirects
			|| 32 < count( $redirects )
			|| Client::AUTH_NONE !== $method
			|| null === $grantTypes
			|| ! is_array( $responses )
			|| array( 'code' ) !== $responses
		) {
			throw new InvalidArgumentException( 'charter_cimd_metadata_invalid' );
		}
		$name = $safeName;

		$accepted = array();
		foreach ( $redirects as $redirect ) {
			if ( ! is_string( $redirect ) || isset( $accepted[ $redirect ] ) || ! RedirectUriValidator::isValid( $redirect ) ) {
				throw new InvalidArgumentException( 'charter_cimd_metadata_invalid' );
			}
			$accepted[ $redirect ] = true;
		}
		$redirectUris = array_keys( $accepted );
		$fingerprint  = self::fingerprint( $clientId, $name, $redirectUris, $grantTypes );

		return new RemoteClientMetadata( $clientId, $name, $redirectUris, $grantTypes, $fingerprint );
	}

	/**
	 * Validates the requested grant-type list.
	 *
	 * @param mixed $candidate Candidate grant list.
	 * @return list<string>|null
	 */
	private static function grantTypes( mixed $candidate ): ?array {
		if ( ! is_array( $candidate ) || ! array_is_list( $candidate ) ) {
			return null;
		}

		$validated = array();
		foreach ( $candidate as $grantType ) {
			if ( ! is_string( $grantType ) || ! in_array( $grantType, array( Client::GRANT_AUTHORIZATION_CODE, Client::GRANT_REFRESH_TOKEN ), true ) ) {
				return null;
			}
			$validated[] = $grantType;
		}

		return in_array( Client::GRANT_AUTHORIZATION_CODE, $validated, true ) && count( $validated ) === count( array_unique( $validated ) ) ? $validated : null;
	}

	/**
	 * Enforces complete depth, node, key-name, and string bounds.
	 *
	 * @param mixed $value Current value.
	 * @param int   $depth Current structural depth.
	 * @param int   $nodes Aggregate node count.
	 */
	private static function hasBoundedStructure( mixed $value, int $depth, int &$nodes ): bool {
		if ( 16 < $depth || 256 < ++$nodes ) {
			return false;
		}
		if ( is_string( $value ) ) {
			return strlen( $value ) <= 2048;
		}
		if ( $value instanceof stdClass ) {
			foreach ( get_object_vars( $value ) as $member => $memberValue ) {
				if ( 128 < strlen( $member ) || ! self::hasBoundedStructure( $memberValue, $depth + 1, $nodes ) ) {
					return false;
				}
			}
		}
		if ( is_array( $value ) ) {
			foreach ( $value as $memberValue ) {
				if ( ! self::hasBoundedStructure( $memberValue, $depth + 1, $nodes ) ) {
					return false;
				}
			}
		}

		return true;
	}

	/**
	 * Rejects duplicate root security members before JSON projection hides them.
	 *
	 * @param string $body Complete JSON body.
	 * @throws InvalidArgumentException When a security member is duplicated.
	 */
	private static function rejectDuplicateSecurityMembers( string $body ): void {
		$seen = array();
		foreach ( self::rootMemberNames( $body ) as $member ) {
			if ( ! in_array( $member, self::SECURITY_MEMBERS, true ) ) {
				continue;
			}
			if ( isset( $seen[ $member ] ) ) {
				throw new InvalidArgumentException( 'charter_cimd_metadata_invalid' );
			}
			$seen[ $member ] = true;
		}
	}

	/**
	 * Finds root object member names, including duplicates.
	 *
	 * @param string $body Complete JSON body.
	 * @return list<string> Root object member names, including duplicates.
	 */
	private static function rootMemberNames( string $body ): array {
		$members     = array();
		$depth       = 0;
		$expectKey   = false;
		$inString    = false;
		$escaped     = false;
		$stringStart = null;
		$length      = strlen( $body );
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
					$key = json_decode( substr( $body, $stringStart, $offset - $stringStart + 1 ), true );
					if ( is_string( $key ) ) {
						$members[] = $key;
					}
					$expectKey = false;
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

		return $members;
	}

	/**
	 * Rejects recoverable private-key members anywhere under an embedded JWK set.
	 *
	 * @param mixed $value Current embedded JWK value.
	 */
	private static function containsPrivateKeyMaterial( mixed $value ): bool {
		if ( $value instanceof stdClass ) {
			foreach ( get_object_vars( $value ) as $name => $member ) {
				if ( in_array( $name, array( 'd', 'p', 'q', 'dp', 'dq', 'qi', 'oth', 'k' ), true ) || self::containsPrivateKeyMaterial( $member ) ) {
					return true;
				}
			}
		}
		if ( is_array( $value ) ) {
			foreach ( $value as $member ) {
				if ( self::containsPrivateKeyMaterial( $member ) ) {
					return true;
				}
			}
		}

		return false;
	}

	/**
	 * Creates an order-independent binding for the user-visible security metadata.
	 *
	 * @param string $clientId Exact client identifier.
	 * @param string $name User-facing client name.
	 * @param array  $redirectUris Exact redirects.
	 * @param array  $grantTypes Exact grant types.
	 * @phpstan-param list<string> $redirectUris
	 * @phpstan-param list<string> $grantTypes
	 * @throws InvalidArgumentException When the canonical projection cannot be encoded.
	 */
	private static function fingerprint( string $clientId, string $name, array $redirectUris, array $grantTypes ): string {
		sort( $redirectUris, SORT_STRING );
		sort( $grantTypes, SORT_STRING );
		$json = wp_json_encode(
			array(
				'client_id'                  => $clientId,
				'client_name'                => $name,
				'redirect_uris'              => $redirectUris,
				'token_endpoint_auth_method' => Client::AUTH_NONE,
				'grant_types'                => $grantTypes,
			),
			JSON_UNESCAPED_SLASHES
		);
		if ( ! is_string( $json ) ) {
			throw new InvalidArgumentException( 'charter_cimd_metadata_invalid' );
		}

		return hash( 'sha256', $json );
	}

	/** Prevents direct construction. */
	private function __construct() {
	}
}
