<?php
/**
 * Disposable CIMD metadata validation boundary.
 *
 * @package GalatanOvidiu\Charter
 */

declare(strict_types=1);

namespace GalatanOvidiu\Charter\Tests\Prototype\CimdOutboundSafety;

use InvalidArgumentException;
use JsonException;
use stdClass;

/**
 * Validates only the bounded public-client metadata accepted by Charter P3.
 *
 * @since 0.1.0
 */
final class MetadataValidator {

	private const MAX_JSON_DEPTH        = 16;
	private const MAX_JSON_NODES        = 256;
	private const MAX_ROOT_MEMBERS      = 64;
	private const MAX_MEMBER_NAME_BYTES = 128;
	private const MAX_STRING_BYTES      = 2048;
	private const MAX_CLIENT_NAME_BYTES = 256;
	private const MAX_REDIRECTS         = 32;

	/**
	 * Security-relevant singleton root members.
	 */
	private const SECURITY_MEMBERS = array(
		'client_id',
		'client_name',
		'redirect_uris',
		'token_endpoint_auth_method',
		'client_secret',
		'client_secret_expires_at',
		'jwks',
		'jwks_uri',
	);

	/**
	 * Validates a complete identity-coded JSON document.
	 *
	 * @since 0.1.0
	 *
	 * @param string           $body       Complete bounded JSON body.
	 * @param ClientIdentifier $identifier Exact submitted identity.
	 * @return ValidatedMetadata Authoritative metadata projection.
	 * @throws InvalidArgumentException When the response cannot become authoritative.
	 */
	public static function validate( string $body, ClientIdentifier $identifier ): ValidatedMetadata {
		if ( '' === $body || 5120 < strlen( $body ) ) {
			throw new InvalidArgumentException( 'The metadata document is invalid.' );
		}

		self::rejectDuplicateSecurityMembers( $body );

		try {
			$decoded = json_decode( $body, false, 64, JSON_THROW_ON_ERROR );
		} catch ( JsonException ) {
			throw new InvalidArgumentException( 'The metadata document is invalid.' );
		}

		$nodeCount = 0;
		if (
			! $decoded instanceof stdClass
			|| self::MAX_ROOT_MEMBERS < count( get_object_vars( $decoded ) )
			|| ! self::hasBoundedStructure( $decoded, 1, $nodeCount )
		) {
			throw new InvalidArgumentException( 'The metadata document is invalid.' );
		}

		$document = get_object_vars( $decoded );

		$clientId             = $document['client_id'] ?? null;
		$clientName           = $document['client_name'] ?? null;
		$redirectUris         = $document['redirect_uris'] ?? null;
		$authenticationMethod = $document['token_endpoint_auth_method'] ?? null;

		if (
			! is_string( $clientId )
			|| $identifier->exact() !== $clientId
			|| ! is_string( $clientName )
			|| '' === $clientName
			|| self::MAX_CLIENT_NAME_BYTES < strlen( $clientName )
			|| ! is_array( $redirectUris )
			|| ! array_is_list( $redirectUris )
			|| array() === $redirectUris
			|| self::MAX_REDIRECTS < count( $redirectUris )
			|| 'none' !== $authenticationMethod
			|| array_key_exists( 'client_secret', $document )
			|| array_key_exists( 'client_secret_expires_at', $document )
			|| self::containsPrivateJwkMaterial( $document['jwks'] ?? null )
		) {
			throw new InvalidArgumentException( 'The metadata document is invalid.' );
		}

		$acceptedRedirects = array();

		foreach ( $redirectUris as $redirectUri ) {
			if (
				! is_string( $redirectUri )
				|| '' === $redirectUri
				|| self::MAX_STRING_BYTES < strlen( $redirectUri )
				|| isset( $acceptedRedirects[ $redirectUri ] )
				|| ! self::isAcceptedRedirect( $redirectUri )
			) {
				throw new InvalidArgumentException( 'The metadata document is invalid.' );
			}

			$acceptedRedirects[ $redirectUri ] = true;
		}

		return new ValidatedMetadata(
			$clientId,
			$clientName,
			array_keys( $acceptedRedirects ),
			$authenticationMethod,
			hash( 'sha256', $body )
		);
	}

	/**
	 * Enforces the approved depth, node, member-name, and string bounds.
	 *
	 * Each object/array container and scalar value is one node. Member names are
	 * bounded separately and do not add to the node count.
	 *
	 * @param mixed $value     Current decoded JSON value.
	 * @param int   $depth     Root-relative depth, with the root object at one.
	 * @param int   $nodeCount Aggregate node count.
	 * @return bool Whether the complete subtree remains bounded.
	 */
	private static function hasBoundedStructure( mixed $value, int $depth, int &$nodeCount ): bool {
		if ( self::MAX_JSON_DEPTH < $depth ) {
			return false;
		}

		++$nodeCount;
		if ( self::MAX_JSON_NODES < $nodeCount ) {
			return false;
		}

		if ( is_string( $value ) ) {
			return strlen( $value ) <= self::MAX_STRING_BYTES;
		}

		if ( $value instanceof stdClass ) {
			foreach ( get_object_vars( $value ) as $member => $memberValue ) {
				if (
					self::MAX_MEMBER_NAME_BYTES < strlen( $member )
					|| ! self::hasBoundedStructure( $memberValue, $depth + 1, $nodeCount )
				) {
					return false;
				}
			}

			return true;
		}

		if ( is_array( $value ) ) {
			foreach ( $value as $memberValue ) {
				if ( ! self::hasBoundedStructure( $memberValue, $depth + 1, $nodeCount ) ) {
					return false;
				}
			}
		}

		return true;
	}

	/**
	 * Rejects duplicate security-relevant keys before JSON projection.
	 *
	 * @param string $body Raw JSON object.
	 * @throws InvalidArgumentException When a security-relevant member repeats.
	 */
	private static function rejectDuplicateSecurityMembers( string $body ): void {
		$members = self::rootMemberNames( $body );
		$seen    = array();

		foreach ( $members as $member ) {
			if ( ! in_array( $member, self::SECURITY_MEMBERS, true ) ) {
				continue;
			}

			if ( isset( $seen[ $member ] ) ) {
				throw new InvalidArgumentException( 'The metadata document is invalid.' );
			}

			$seen[ $member ] = true;
		}
	}

	/**
	 * Extracts root member names without projecting duplicate keys away.
	 *
	 * @param string $body Raw JSON object.
	 * @return list<string> Root member names.
	 */
	private static function rootMemberNames( string $body ): array {
		$length      = strlen( $body );
		$depth       = 0;
		$expectKey   = false;
		$inString    = false;
		$escaped     = false;
		$stringStart = null;
		$members     = array();

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
					$quoted = substr( $body, $stringStart, $offset - $stringStart + 1 );
					$key    = json_decode( $quoted, true );

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
				continue;
			}

			if ( '{' === $character || '[' === $character ) {
				++$depth;
				if ( 1 === $depth && '{' === $character ) {
					$expectKey = true;
				}
				continue;
			}

			if ( '}' === $character || ']' === $character ) {
				--$depth;
				continue;
			}

			if ( 1 === $depth && ',' === $character ) {
				$expectKey = true;
			}
		}

		return $members;
	}

	/**
	 * Checks the exact redirect classes accepted by D07.
	 *
	 * @param string $redirectUri Redirect URI.
	 * @return bool Whether the redirect is accepted.
	 */
	private static function isAcceptedRedirect( string $redirectUri ): bool {
		if (
			1 === preg_match( '/[^\x21-\x7e]/', $redirectUri )
			|| str_contains( $redirectUri, '\\' )
			|| 1 === preg_match( '/%(?![0-9A-Fa-f]{2})/', $redirectUri )
		) {
			return false;
		}

		// phpcs:ignore WordPress.WP.AlternativeFunctions.parse_url_parse_url -- Standalone proof value does not bootstrap WordPress.
		$parts = parse_url( $redirectUri );

		if (
			! is_array( $parts )
			|| ! is_string( $parts['scheme'] ?? null )
			|| ! is_string( $parts['host'] ?? null )
			|| '' === $parts['host']
			|| isset( $parts['user'] )
			|| isset( $parts['pass'] )
			|| isset( $parts['fragment'] )
			|| ! self::isValidRedirectHost( $parts['host'] )
			|| ( isset( $parts['port'] ) && 1 > $parts['port'] )
		) {
			return false;
		}

		if ( 0 === strcasecmp( 'https', $parts['scheme'] ) ) {
			return true;
		}

		return 0 === strcasecmp( 'http', $parts['scheme'] )
			&& in_array( strtolower( $parts['host'] ), array( 'localhost', '127.0.0.1', '[::1]' ), true );
	}

	/**
	 * Validates one exact DNS, IPv4, or bracketed IPv6 redirect host.
	 *
	 * @param string $host Parsed redirect host.
	 * @return bool Whether the host has an unambiguous URL spelling.
	 */
	private static function isValidRedirectHost( string $host ): bool {
		if ( str_starts_with( $host, '[' ) || str_ends_with( $host, ']' ) ) {
			if ( ! str_starts_with( $host, '[' ) || ! str_ends_with( $host, ']' ) ) {
				return false;
			}

			$literal = substr( $host, 1, -1 );
			return false !== filter_var( $literal, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6 );
		}

		if (
			str_contains( $host, '[' )
			|| str_contains( $host, ']' )
			|| str_contains( $host, ':' )
			|| str_contains( $host, '%' )
			|| 253 < strlen( $host )
		) {
			return false;
		}

		if ( false !== filter_var( $host, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4 ) ) {
			return true;
		}

		if ( 1 === preg_match( '/\A[0-9.]+\z/D', $host ) ) {
			return false;
		}

		$labels = explode( '.', rtrim( $host, '.' ) );
		foreach ( $labels as $label ) {
			if (
				'' === $label
				|| 63 < strlen( $label )
				|| 1 !== preg_match( '/\A[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?\z/D', $label )
			) {
				return false;
			}
		}

		return true;
	}

	/**
	 * Detects private or symmetric JWK members recursively.
	 *
	 * @param mixed $value Optional JWK set.
	 * @return bool Whether private material is present.
	 */
	private static function containsPrivateJwkMaterial( mixed $value ): bool {
		if ( $value instanceof stdClass ) {
			$value = get_object_vars( $value );
		}

		if ( ! is_array( $value ) ) {
			return false;
		}

		foreach ( $value as $member => $memberValue ) {
			if ( is_string( $member ) && in_array( $member, array( 'd', 'p', 'q', 'dp', 'dq', 'qi', 'k' ), true ) ) {
				return true;
			}

			if ( self::containsPrivateJwkMaterial( $memberValue ) ) {
				return true;
			}
		}

		return false;
	}
}
