<?php
/**
 * Bounded DNS wire query through the system-configured recursive resolver.
 *
 * @package GalatanOvidiu\Charter
 */

declare(strict_types=1);

namespace GalatanOvidiu\Charter\Security;

use RuntimeException;

// The DNS safety boundary requires exact bounded socket and resolv.conf I/O.
// phpcs:disable WordPress.PHP.NoSilencedErrors.Discouraged
// phpcs:disable WordPress.WP.AlternativeFunctions.file_system_operations_file
// phpcs:disable WordPress.WP.AlternativeFunctions.file_system_operations_fwrite
// phpcs:disable WordPress.WP.AlternativeFunctions.file_system_operations_fread
// phpcs:disable WordPress.WP.AlternativeFunctions.file_system_operations_fclose

/** Converts one DNS response into sanitized A, AAAA, and CNAME records. */
final class SystemDnsQuery {

	/**
	 * Resolves one record type through the configured recursive resolver.
	 *
	 * @param string $name Exact DNS name.
	 * @param string $type Exact requested record type.
	 * @param int    $remainingMilliseconds Remaining aggregate budget.
	 * @return list<array<string,mixed>> One sanitized DNS message or an empty timeout result.
	 */
	public function __invoke( string $name, string $type, int $remainingMilliseconds ): array {
		$typeNumber = array(
			'A'    => 1,
			'AAAA' => 28,
		)[ $type ] ?? null;
		if ( ! is_int( $typeNumber ) || 0 >= $remainingMilliseconds || 1000 < $remainingMilliseconds ) {
			return array( self::malformed( 0 ) );
		}
		$server = self::nameServer();
		if ( null === $server ) {
			return array( self::malformed( 0 ) );
		}

		$id     = random_int( 1, 65535 );
		$query  = pack( 'nnnnnn', $id, 0x0100, 1, 0, 0, 0 ) . self::encodeName( $name ) . pack( 'nn', $typeNumber, 1 );
		$uri    = str_contains( $server, ':' ) ? 'udp://[' . $server . ']:53' : 'udp://' . $server . ':53';
		$socket = @stream_socket_client( $uri, $errorNumber, $errorMessage, $remainingMilliseconds / 1000 ); // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_stream_socket_client -- Direct bounded DNS transport is the security boundary.
		unset( $errorNumber, $errorMessage );
		if ( false === $socket ) {
			return array();
		}
		stream_set_timeout( $socket, intdiv( $remainingMilliseconds, 1000 ), ( $remainingMilliseconds % 1000 ) * 1000 );
		$written = @fwrite( $socket, $query );
		$packet  = strlen( $query ) === $written ? @fread( $socket, 16385 ) : false;
		fclose( $socket );
		if ( ! is_string( $packet ) || '' === $packet ) {
			return array();
		}

		return array( self::parse( $packet, $id, $name, $typeNumber ) );
	}

	/** Returns the first exact IP nameserver from resolv.conf. */
	private static function nameServer(): ?string {
		$lines = @file( '/etc/resolv.conf', FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES );
		if ( ! is_array( $lines ) ) {
			return null;
		}
		foreach ( $lines as $line ) {
			if ( 1 === preg_match( '/^\s*nameserver\s+([^\s#]+)(?:\s|#|$)/', $line, $matches ) ) {
				$address = $matches[1];
				if ( false !== filter_var( $address, FILTER_VALIDATE_IP ) ) {
					return $address;
				}
			}
		}

		return null;
	}

	/**
	 * Encodes one already validated DNS host.
	 *
	 * @param string $name Exact DNS name.
	 * @throws RuntimeException When a label is invalid.
	 */
	private static function encodeName( string $name ): string {
		$wire = '';
		foreach ( explode( '.', rtrim( $name, '.' ) ) as $label ) {
			if ( '' === $label || 63 < strlen( $label ) ) {
				throw new RuntimeException( 'charter_dns_name_invalid' );
			}
			$wire .= chr( strlen( $label ) ) . $label;
		}

		return $wire . "\0";
	}

	/**
	 * Parses and validates one complete DNS response packet.
	 *
	 * @param string $packet Complete DNS packet.
	 * @param int    $expectedId Expected transaction identifier.
	 * @param string $expectedName Expected question name.
	 * @param int    $expectedType Expected question type.
	 * @return array<string,mixed> Sanitized DNS message.
	 * @throws RuntimeException When packet parsing cannot begin.
	 */
	private static function parse( string $packet, int $expectedId, string $expectedName, int $expectedType ): array {
		$wireBytes = strlen( $packet );
		try {
			if ( 12 > $wireBytes || 16384 < $wireBytes ) {
				throw new RuntimeException( 'charter_dns_response_invalid' );
			}
			$header = unpack( 'nid/nflags/nqd/nan/nns/nar', substr( $packet, 0, 12 ) );
			if ( ! is_array( $header ) ) {
				throw new RuntimeException( 'charter_dns_response_invalid' );
			}
			$id              = self::integer( $header, 'id' );
			$flags           = self::integer( $header, 'flags' );
			$questionCount   = self::integer( $header, 'qd' );
			$answerCount     = self::integer( $header, 'an' );
			$authorityCount  = self::integer( $header, 'ns' );
			$additionalCount = self::integer( $header, 'ar' );
			if ( $id !== $expectedId || 1 !== $questionCount || 0 === ( $flags & 0x8000 ) ) {
				throw new RuntimeException( 'charter_dns_response_invalid' );
			}

			$offset       = 12;
			$questionName = self::readName( $packet, $offset );
			if ( $offset + 4 > $wireBytes ) {
				throw new RuntimeException( 'charter_dns_response_invalid' );
			}
			$question = unpack( 'ntype/nclass', substr( $packet, $offset, 4 ) );
			if ( ! is_array( $question ) || self::integer( $question, 'type' ) !== $expectedType || 1 !== self::integer( $question, 'class' ) || strtolower( rtrim( $questionName, '.' ) ) !== strtolower( rtrim( $expectedName, '.' ) ) ) {
				throw new RuntimeException( 'charter_dns_response_invalid' );
			}
			$offset += 4;

			$records = array();
			$count   = $answerCount + $authorityCount + $additionalCount;
			for ( $index = 0; $index < $count; ++$index ) {
				$owner = self::readName( $packet, $offset );
				if ( $offset + 10 > $wireBytes ) {
					throw new RuntimeException( 'charter_dns_response_invalid' );
				}
				$fields  = unpack( 'ntype/nclass/Nttl/nlength', substr( $packet, $offset, 10 ) );
				$offset += 10;
				if ( ! is_array( $fields ) ) {
					throw new RuntimeException( 'charter_dns_response_invalid' );
				}
				$recordType   = self::integer( $fields, 'type' );
				$recordClass  = self::integer( $fields, 'class' );
				$recordLength = self::integer( $fields, 'length' );
				self::integer( $fields, 'ttl' );
				if ( 1 !== $recordClass || 0 > $recordLength || $offset + $recordLength > $wireBytes ) {
					throw new RuntimeException( 'charter_dns_response_invalid' );
				}

				$type  = 'OTHER';
				$value = 'ignored';
				if ( 1 === $recordType && 4 === $recordLength ) {
					$type  = 'A';
					$value = inet_ntop( substr( $packet, $offset, 4 ) );
				} elseif ( 28 === $recordType && 16 === $recordLength ) {
					$type  = 'AAAA';
					$value = inet_ntop( substr( $packet, $offset, 16 ) );
				} elseif ( 5 === $recordType ) {
					$type        = 'CNAME';
					$valueOffset = $offset;
					$value       = self::readName( $packet, $valueOffset );
					if ( $valueOffset !== $offset + $recordLength ) {
						throw new RuntimeException( 'charter_dns_response_invalid' );
					}
				}
				if ( ! is_string( $value ) || '' === $value ) {
					throw new RuntimeException( 'charter_dns_response_invalid' );
				}
				$records[] = array(
					'type'  => $type,
					'name'  => $owner,
					'value' => $value,
				);
				$offset   += $recordLength;
			}
			if ( $offset !== $wireBytes ) {
				throw new RuntimeException( 'charter_dns_response_invalid' );
			}

			$status = array(
				0 => 'NOERROR',
				2 => 'SERVFAIL',
				3 => 'NXDOMAIN',
			)[ $flags & 0x000f ] ?? 'INVALID';
			return array(
				'status'     => $status,
				'truncated'  => 0 !== ( $flags & 0x0200 ),
				'malformed'  => false,
				'wire_bytes' => $wireBytes,
				'records'    => $records,
			);
		} catch ( RuntimeException ) {
			return self::malformed( $wireBytes );
		}
	}

	/**
	 * Reads one bounded possibly compressed DNS name.
	 *
	 * @param string $packet Complete DNS packet.
	 * @param int    $offset Mutable packet offset.
	 * @param int    $depth Pointer recursion depth.
	 * @throws RuntimeException When the name is malformed.
	 */
	private static function readName( string $packet, int &$offset, int $depth = 0 ): string {
		if ( 16 < $depth ) {
			throw new RuntimeException( 'charter_dns_response_invalid' );
		}
		$labels = array();
		$length = strlen( $packet );
		while ( $offset < $length ) {
			$size = ord( $packet[ $offset ] );
			if ( 0 === $size ) {
				++$offset;
				return implode( '.', $labels );
			}
			if ( 0xc0 === ( $size & 0xc0 ) ) {
				if ( $offset + 1 >= $length ) {
					throw new RuntimeException( 'charter_dns_response_invalid' );
				}
				$target   = ( ( $size & 0x3f ) << 8 ) | ord( $packet[ $offset + 1 ] );
				$offset  += 2;
				$labels[] = self::readName( $packet, $target, $depth + 1 );
				return implode( '.', $labels );
			}
			if ( 63 < $size || $offset + 1 + $size > $length ) {
				throw new RuntimeException( 'charter_dns_response_invalid' );
			}
			++$offset;
			$labels[] = substr( $packet, $offset, $size );
			$offset  += $size;
		}

		throw new RuntimeException( 'charter_dns_response_invalid' );
	}

	/**
	 * Reads one required integer field.
	 *
	 * @param array<mixed> $fields Parsed fields.
	 * @param string       $name Required field name.
	 * @throws RuntimeException When the field is missing or invalid.
	 */
	private static function integer( array $fields, string $name ): int {
		$value = $fields[ $name ] ?? null;
		if ( ! is_int( $value ) ) {
			throw new RuntimeException( 'charter_dns_response_invalid' );
		}

		return $value;
	}

	/**
	 * Creates one bounded malformed response projection.
	 *
	 * @param int $wireBytes Observed packet bytes.
	 * @return array<string,mixed> Sanitized malformed response.
	 */
	private static function malformed( int $wireBytes ): array {
		return array(
			'status'     => 'INVALID',
			'truncated'  => false,
			'malformed'  => true,
			'wire_bytes' => min( 16384, max( 0, $wireBytes ) ),
			'records'    => array(),
		);
	}
}
