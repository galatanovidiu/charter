<?php
/**
 * Bounded client for the disposable hostile DNS fixture.
 *
 * @package GalatanOvidiu\Charter
 */

declare(strict_types=1);

namespace GalatanOvidiu\Charter\Tests\Integration\CimdOutboundSafety;

use RuntimeException;

// Exact fixture-network I/O has no WordPress filesystem abstraction.
// phpcs:disable WordPress.PHP.NoSilencedErrors.Discouraged
// phpcs:disable WordPress.WP.AlternativeFunctions.file_system_operations_fwrite
// phpcs:disable WordPress.WP.AlternativeFunctions.file_system_operations_fread
// phpcs:disable WordPress.WP.AlternativeFunctions.file_system_operations_fclose

/**
 * Converts one proof-owned DNS wire response into the resolver's sanitized seam.
 *
 * @since 0.1.0
 */
final class FixtureDnsQuery {

	/**
	 * Creates a query boundary for one exact fixture endpoint.
	 *
	 * @param string $server IPv4 address and port.
	 * @throws RuntimeException For an invalid fixed fixture endpoint.
	 */
	public function __construct( private readonly string $server ) {
		if ( 1 !== preg_match( '/\A[0-9.]+:[0-9]+\z/', $server ) ) {
			throw new RuntimeException( 'The proof DNS fixture endpoint is invalid.' );
		}
	}

	/**
	 * Sends one bounded A or AAAA query and returns no raw wire data.
	 *
	 * @param string $name                  Exact DNS owner.
	 * @param string $type                  A or AAAA.
	 * @param int    $remainingMilliseconds Remaining aggregate deadline.
	 * @return list<array<string, mixed>> Sanitized DNS messages.
	 * @throws RuntimeException For an invalid query name.
	 */
	public function __invoke( string $name, string $type, int $remainingMilliseconds = 1000 ): array {
		$typeNumber = array(
			'A'    => 1,
			'AAAA' => 28,
		)[ $type ] ?? null;
		if ( ! is_int( $typeNumber ) || $remainingMilliseconds <= 0 || 1000 < $remainingMilliseconds ) {
			return array( self::malformedMessage( 0 ) );
		}

		$query = pack( 'nnnnnn', 0x5033, 0x0100, 1, 0, 0, 0 )
			. self::encodeName( $name )
			. pack( 'nn', $typeNumber, 1 );

		// phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_stream_socket_client -- Exact non-egressing DNS fixture seam.
		$socket = @stream_socket_client(
			'udp://' . $this->server,
			$errorNumber,
			$errorMessage,
			$remainingMilliseconds / 1000
		);
		unset( $errorNumber, $errorMessage );
		if ( false === $socket ) {
			return array();
		}

		stream_set_timeout(
			$socket,
			intdiv( $remainingMilliseconds, 1000 ),
			( $remainingMilliseconds % 1000 ) * 1000
		);
		$written = @fwrite( $socket, $query );
		$packet  = strlen( $query ) === $written ? @fread( $socket, 16384 ) : false;
		fclose( $socket );

		if ( ! is_string( $packet ) || '' === $packet ) {
			return array();
		}

		return array( self::parseMessage( $packet, $name, $typeNumber ) );
	}

	/**
	 * Encodes one bounded query name.
	 *
	 * @param string $name DNS name.
	 * @throws RuntimeException For an invalid query name.
	 */
	private static function encodeName( string $name ): string {
		$wire = '';
		foreach ( explode( '.', $name ) as $label ) {
			if ( '' === $label || 63 < strlen( $label ) ) {
				throw new RuntimeException( 'The proof DNS query name is invalid.' );
			}
			$wire .= chr( strlen( $label ) ) . $label;
		}

		return $wire . "\0";
	}

	/**
	 * Parses only the fields consumed by BoundedResolver.
	 *
	 * @param string $packet             Complete bounded DNS packet.
	 * @param string $expectedName       Exact queried owner.
	 * @param int    $expectedTypeNumber Exact queried type number.
	 * @return array<string, mixed> Sanitized message.
	 * @throws RuntimeException Internally for malformed packets; converted to a sentinel.
	 */
	private static function parseMessage( string $packet, string $expectedName, int $expectedTypeNumber ): array {
		$wireBytes = strlen( $packet );
		try {
			if ( $wireBytes < 12 || 16384 < $wireBytes ) {
				throw new RuntimeException( 'Malformed DNS fixture response.' );
			}

			$header = unpack( 'nid/nflags/nqd/nan/nns/nar', substr( $packet, 0, 12 ) );
			if ( ! is_array( $header ) ) {
				throw new RuntimeException( 'Malformed DNS fixture response.' );
			}
			$id              = self::integerField( $header, 'id' );
			$flags           = self::integerField( $header, 'flags' );
			$questionCount   = self::integerField( $header, 'qd' );
			$answerCount     = self::integerField( $header, 'an' );
			$authorityCount  = self::integerField( $header, 'ns' );
			$additionalCount = self::integerField( $header, 'ar' );
			if ( 0x5033 !== $id || 1 !== $questionCount || 0 === ( $flags & 0x8000 ) ) {
				throw new RuntimeException( 'Malformed DNS fixture response.' );
			}

			$offset       = 12;
			$questionName = self::readName( $packet, $offset );
			if ( $offset + 4 > $wireBytes ) {
				throw new RuntimeException( 'Malformed DNS fixture response.' );
			}
			$question = unpack( 'ntype/nclass', substr( $packet, $offset, 4 ) );
			if ( ! is_array( $question ) ) {
				throw new RuntimeException( 'Malformed DNS fixture response.' );
			}
			$questionType  = self::integerField( $question, 'type' );
			$questionClass = self::integerField( $question, 'class' );
			if (
				strtolower( $expectedName ) !== strtolower( $questionName )
				|| $expectedTypeNumber !== $questionType
				|| 1 !== $questionClass
			) {
				throw new RuntimeException( 'Malformed DNS fixture response.' );
			}
			$offset += 4;

			$records     = array();
			$recordCount = $answerCount + $authorityCount + $additionalCount;
			for ( $index = 0; $index < $recordCount; ++$index ) {
				$owner = self::readName( $packet, $offset );
				if ( $offset + 10 > $wireBytes ) {
					throw new RuntimeException( 'Malformed DNS fixture response.' );
				}

				$fields  = unpack( 'ntype/nclass/Nttl/nlength', substr( $packet, $offset, 10 ) );
				$offset += 10;
				if ( ! is_array( $fields ) ) {
					throw new RuntimeException( 'Malformed DNS fixture response.' );
				}
				$recordType   = self::integerField( $fields, 'type' );
				$recordClass  = self::integerField( $fields, 'class' );
				$recordLength = self::integerField( $fields, 'length' );
				self::integerField( $fields, 'ttl' );
				if ( 1 !== $recordClass || $recordLength < 0 || $offset + $recordLength > $wireBytes ) {
					throw new RuntimeException( 'Malformed DNS fixture response.' );
				}

				$value = false;
				$type  = 'OTHER';
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
						throw new RuntimeException( 'Malformed DNS fixture response.' );
					}
				} else {
					$value = 'ignored';
				}

				if ( is_string( $value ) && '' !== $value ) {
					$records[] = array(
						'type'  => $type,
						'name'  => $owner,
						'value' => $value,
					);
				}

				$offset += $recordLength;
			}
			if ( $offset !== $wireBytes ) {
				throw new RuntimeException( 'Malformed DNS fixture response.' );
			}

			$rcode  = $flags & 0x000f;
			$status = array(
				0 => 'NOERROR',
				2 => 'SERVFAIL',
				3 => 'NXDOMAIN',
			)[ $rcode ] ?? 'INVALID';

			return array(
				'status'     => $status,
				'truncated'  => 0 !== ( $flags & 0x0200 ),
				'malformed'  => false,
				'wire_bytes' => $wireBytes,
				'records'    => $records,
			);
		} catch ( RuntimeException ) {
			return self::malformedMessage( $wireBytes );
		}
	}

	/**
	 * Reads one required integer returned by unpack().
	 *
	 * @param array<mixed> $fields Untrusted unpacked fields.
	 * @param string       $name   Required field name.
	 * @throws RuntimeException For absent or non-integer fields.
	 */
	private static function integerField( array $fields, string $name ): int {
		$value = $fields[ $name ] ?? null;
		if ( ! is_int( $value ) ) {
			throw new RuntimeException( 'Malformed DNS fixture response.' );
		}

		return $value;
	}

	/**
	 * Reads one possibly compressed DNS name with a fixed pointer-depth bound.
	 *
	 * @param string $packet Complete packet.
	 * @param int    $offset Current packet offset.
	 * @param int    $depth  Compression-pointer depth.
	 * @throws RuntimeException For malformed or cyclic compression.
	 */
	private static function readName( string $packet, int &$offset, int $depth = 0 ): string {
		if ( 16 < $depth ) {
			throw new RuntimeException( 'Malformed DNS fixture response.' );
		}

		$labels = array();
		$length = strlen( $packet );
		while ( $offset < $length ) {
			$labelLength = ord( $packet[ $offset ] );
			if ( 0 === $labelLength ) {
				++$offset;
				return implode( '.', $labels );
			}

			if ( 0xc0 === ( $labelLength & 0xc0 ) ) {
				if ( $offset + 1 >= $length ) {
					throw new RuntimeException( 'Malformed DNS fixture response.' );
				}
				$pointer  = ( ( $labelLength & 0x3f ) << 8 ) | ord( $packet[ $offset + 1 ] );
				$offset  += 2;
				$target   = $pointer;
				$labels[] = self::readName( $packet, $target, $depth + 1 );
				return implode( '.', $labels );
			}

			if ( 63 < $labelLength || $offset + 1 + $labelLength > $length ) {
				throw new RuntimeException( 'Malformed DNS fixture response.' );
			}

			++$offset;
			$labels[] = substr( $packet, $offset, $labelLength );
			$offset  += $labelLength;
		}

		throw new RuntimeException( 'Malformed DNS fixture response.' );
	}

	/**
	 * Returns one sanitized malformed sentinel.
	 *
	 * @param int $wireBytes Observed bounded bytes.
	 * @return array<string, mixed> Message.
	 */
	private static function malformedMessage( int $wireBytes ): array {
		return array(
			'status'     => 'INVALID',
			'truncated'  => false,
			'malformed'  => true,
			'wire_bytes' => min( 16384, max( 0, $wireBytes ) ),
			'records'    => array(),
		);
	}
}
