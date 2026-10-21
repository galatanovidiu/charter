<?php
/**
 * Trusted reverse-proxy authority boundary.
 *
 * @package GalatanOvidiu\Charter
 */

declare(strict_types=1);

namespace GalatanOvidiu\Charter\Security;

/** Accepts forwarded origin and source data only from configured network peers. */
final class TrustedProxyPolicy {

	/**
	 * Parsed network prefixes.
	 *
	 * @var list<array{network:string,bits:int}>
	 */
	private array $networks = array();

	/**
	 * Whether the configured value is structurally valid.
	 *
	 * @var bool
	 */
	private bool $valid = true;

	/**
	 * Whether at least one trusted proxy was configured.
	 *
	 * @var bool
	 */
	private bool $configured = false;

	/**
	 * Creates the policy from explicit entries or WordPress deployment config.
	 *
	 * @param array<mixed>|null $entries Exact IP or CIDR entries; null reads CHARTER_TRUSTED_PROXIES.
	 */
	public function __construct( ?array $entries = null ) {
		if ( null === $entries ) {
			if ( ! defined( 'CHARTER_TRUSTED_PROXIES' ) ) {
				return;
			}
			$configured = constant( 'CHARTER_TRUSTED_PROXIES' );
			if ( ! is_array( $configured ) ) {
				$this->valid = false;
				return;
			}
			$entries = $configured;
		}

		$this->configured = array() !== $entries;
		foreach ( $entries as $entry ) {
			$network = is_string( $entry ) ? self::parseNetwork( $entry ) : null;
			if ( null === $network ) {
				$this->valid    = false;
				$this->networks = array();
				return;
			}
			$this->networks[] = $network;
		}
	}

	/** Reports whether the complete configuration is valid. */
	public function configurationValid(): bool {
		return $this->valid;
	}

	/** Reports whether at least one trusted proxy was configured. */
	public function configured(): bool {
		return $this->configured;
	}

	/**
	 * Returns the authoritative client source, grouping IPv6 by /64.
	 *
	 * @param array<mixed> $server Request server variables.
	 */
	public function sourceAddress( array $server ): string {
		$remote = $server['REMOTE_ADDR'] ?? null;
		$direct = is_string( $remote ) ? self::normalizeAddress( $remote ) : null;
		if ( null === $direct ) {
			return 'unknown';
		}
		if ( ! $this->valid || ! is_string( $remote ) || ! $this->matchesTrustedNetwork( $remote ) ) {
			return $direct;
		}

		$forwarded = $server['HTTP_X_FORWARDED_FOR'] ?? null;
		if ( null === $forwarded ) {
			return $direct;
		}
		if ( ! is_string( $forwarded ) || '' === $forwarded ) {
			return $direct;
		}
		if ( 4096 < strlen( $forwarded ) ) {
			$forwarded = substr( $forwarded, -4096 );
			$separator = strpos( $forwarded, ',' );
			if ( false === $separator ) {
				return $direct;
			}
			$forwarded = substr( $forwarded, $separator + 1 );
		}

		$addresses = array_map( 'trim', explode( ',', $forwarded ) );
		if ( 32 < count( $addresses ) ) {
			$addresses = array_slice( $addresses, -32 );
		}

		$chain = array_merge( $addresses, array( $remote ) );
		for ( $index = count( $chain ) - 1; $index >= 0; --$index ) {
			$normalized = self::normalizeAddress( $chain[ $index ] );
			if ( null === $normalized ) {
				continue;
			}
			if ( $this->matchesTrustedNetwork( $chain[ $index ] ) ) {
				continue;
			}

			return $normalized;
		}

		return self::normalizeAddress( $addresses[0] ) ?? $direct;
	}

	/**
	 * Returns the request's public origin or null for malformed trusted input.
	 *
	 * @param array<mixed> $server Request server variables.
	 * @param bool         $directHttps Whether the direct request uses HTTPS.
	 */
	public function publicOrigin( array $server, bool $directHttps ): ?string {
		$directHost = $server['HTTP_HOST'] ?? null;
		if ( ! is_string( $directHost ) || ! self::validForwardedHost( $directHost ) ) {
			return null;
		}
		$directOrigin = ( $directHttps ? 'https://' : 'http://' ) . $directHost;
		$remote       = $server['REMOTE_ADDR'] ?? null;
		if ( ! $this->valid ) {
			return null;
		}
		if ( ! is_string( $remote ) || ! $this->matchesTrustedNetwork( $remote ) ) {
			return $directOrigin;
		}

		$forwardedHost  = $server['HTTP_X_FORWARDED_HOST'] ?? null;
		$forwardedProto = $server['HTTP_X_FORWARDED_PROTO'] ?? null;
		$forwardedPort  = $server['HTTP_X_FORWARDED_PORT'] ?? null;
		if ( null === $forwardedHost && null === $forwardedProto && null === $forwardedPort ) {
			return $directOrigin;
		}

		$host        = null === $forwardedHost ? $directHost : $forwardedHost;
		$schemeValue = null === $forwardedProto ? ( $directHttps ? 'https' : 'http' ) : $forwardedProto;
		if ( ! is_string( $host ) || ! is_string( $schemeValue ) || ! self::validForwardedHost( $host ) ) {
			return null;
		}
		$scheme = strtolower( $schemeValue );
		if ( ! in_array( $scheme, array( 'http', 'https' ), true ) ) {
			return null;
		}
		if ( null !== $forwardedPort ) {
			if ( ! is_string( $forwardedPort ) || 1 !== preg_match( '/^[0-9]{1,5}$/D', $forwardedPort ) || (int) $forwardedPort < 1 || 65535 < (int) $forwardedPort || self::hostIncludesPort( $host ) ) {
				return null;
			}
			$host .= ':' . $forwardedPort;
		}

		return $scheme . '://' . $host;
	}

	/**
	 * Reports whether the immediate peer is trusted.
	 *
	 * @param array<mixed> $server Request server variables.
	 */
	public function immediatePeerTrusted( array $server ): bool {
		$remote = $server['REMOTE_ADDR'] ?? null;

		return $this->valid && is_string( $remote ) && $this->matchesTrustedNetwork( $remote );
	}

	/**
	 * Parses one exact IP or CIDR prefix.
	 *
	 * @param string $entry Configured entry.
	 * @return array{network:string,bits:int}|null
	 */
	private static function parseNetwork( string $entry ): ?array {
		$parts   = explode( '/', trim( $entry ), 2 );
		$address = $parts[0];
		$packed  = inet_pton( $address );
		if ( false === $packed ) {
			return null;
		}
		$mapped = self::isIpv4Mapped( $packed );
		if ( $mapped ) {
			$packed = substr( $packed, 12 );
		}
		$maximum = 8 * strlen( $packed );
		$bits    = $maximum;
		if ( isset( $parts[1] ) ) {
			if ( 1 !== preg_match( '/^[0-9]{1,3}$/D', $parts[1] ) ) {
				return null;
			}
			$bits = (int) $parts[1];
			if ( $mapped ) {
				if ( $bits < 96 ) {
					return null;
				}
				$bits -= 96;
			}
		}
		if ( $bits < 0 || $maximum < $bits ) {
			return null;
		}

		return array(
			'network' => $packed,
			'bits'    => $bits,
		);
	}

	/**
	 * Reports whether one exact address belongs to a configured trusted prefix.
	 *
	 * @param string $address Candidate peer address.
	 */
	private function matchesTrustedNetwork( string $address ): bool {
		$packed = self::packedAddress( $address );
		if ( false === $packed ) {
			return false;
		}

		foreach ( $this->networks as $network ) {
			if ( strlen( $packed ) !== strlen( $network['network'] ) ) {
				continue;
			}
			$wholeBytes = intdiv( $network['bits'], 8 );
			$remaining  = $network['bits'] % 8;
			if ( substr( $packed, 0, $wholeBytes ) !== substr( $network['network'], 0, $wholeBytes ) ) {
				continue;
			}
			if ( 0 === $remaining ) {
				return true;
			}
			$mask = ( 0xFF << ( 8 - $remaining ) ) & 0xFF;
			if ( ( ord( $packed[ $wholeBytes ] ) & $mask ) === ( ord( $network['network'][ $wholeBytes ] ) & $mask ) ) {
				return true;
			}
		}

		return false;
	}

	/**
	 * Returns one canonical source bucket or null for an invalid address.
	 *
	 * @param string $address Candidate source address.
	 */
	private static function normalizeAddress( string $address ): ?string {
		$packed = self::packedAddress( $address );
		if ( false === $packed ) {
			return null;
		}
		if ( 16 === strlen( $packed ) ) {
			$packed = substr( $packed, 0, 8 ) . str_repeat( "\0", 8 );
		}

		$normalized = inet_ntop( $packed );

		return is_string( $normalized ) ? $normalized : null;
	}

	/**
	 * Returns a canonical binary address, unmapping IPv4-mapped IPv6.
	 *
	 * @param string $address Candidate source address.
	 */
	private static function packedAddress( string $address ): string|false {
		$packed = inet_pton( $address );
		if ( false === $packed ) {
			return false;
		}

		return self::isIpv4Mapped( $packed ) ? substr( $packed, 12 ) : $packed;
	}

	/**
	 * Reports whether a binary address is an IPv4-mapped IPv6 value.
	 *
	 * @param string $packed Binary network address.
	 */
	private static function isIpv4Mapped( string $packed ): bool {
		return 16 === strlen( $packed ) && str_repeat( "\0", 10 ) . "\xFF\xFF" === substr( $packed, 0, 12 );
	}

	/**
	 * Reports whether one forwarded host is a single bounded authority value.
	 *
	 * @param string $host Candidate host authority.
	 */
	private static function validForwardedHost( string $host ): bool {
		return '' !== $host
			&& strlen( $host ) <= 2048
			&& 0 === preg_match( '~[\x00-\x20\x7F,\\\\/?#@]~', $host );
	}

	/**
	 * Reports whether a host authority already carries an explicit port.
	 *
	 * @param string $host Candidate host authority.
	 */
	private static function hostIncludesPort( string $host ): bool {
		return 1 === preg_match( '/\]:[0-9]+$/D', $host ) || 1 === preg_match( '/^[^:]+:[0-9]+$/D', $host );
	}
}
