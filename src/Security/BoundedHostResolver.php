<?php
/**
 * Complete bounded DNS resolution for untrusted outbound metadata.
 *
 * @package GalatanOvidiu\Charter
 */

declare(strict_types=1);

namespace GalatanOvidiu\Charter\Security;

use Closure;
use GalatanOvidiu\Charter\OAuth\ClientMetadataResolutionException;

/** Traverses A, AAAA, and CNAME data within one aggregate deadline. */
final class BoundedHostResolver implements HostAddressResolver {

	private const MAX_CNAME_HOPS      = 8;
	private const MAX_ADDRESSES       = 32;
	private const MAX_RECORDS         = 64;
	private const MAX_MESSAGES        = 16;
	private const MAX_MESSAGE_BYTES   = 16384;
	private const MAX_AGGREGATE_BYTES = 65536;
	private const DEADLINE_MS         = 1000;

	/**
	 * Bounded DNS packet boundary.
	 *
	 * @var Closure(string,string,int):mixed
	 */
	private readonly Closure $query;

	/**
	 * Monotonic resolution start.
	 *
	 * @var int
	 */
	private int $startedAt = 0;

	/**
	 * Aggregate record count.
	 *
	 * @var int
	 */
	private int $recordCount = 0;

	/**
	 * Aggregate message count.
	 *
	 * @var int
	 */
	private int $messageCount = 0;

	/**
	 * Aggregate DNS wire bytes.
	 *
	 * @var int
	 */
	private int $wireBytes = 0;

	/**
	 * Aggregate address record count.
	 *
	 * @var int
	 */
	private int $addressCount = 0;

	/**
	 * Exact CNAME targets by normalized owner.
	 *
	 * @var array<string,array<string,string>>
	 */
	private array $cnameTargets = array();

	/**
	 * Exact addresses by normalized owner.
	 *
	 * @var array<string,list<string>>
	 */
	private array $addresses = array();

	/**
	 * Creates the bounded complete resolver.
	 *
	 * @param callable|null $query Injectable bounded DNS packet boundary.
	 * @phpstan-param (callable(string,string,int):mixed)|null $query
	 */
	public function __construct( ?callable $query = null ) {
		$this->query = Closure::fromCallable( $query ?? new SystemDnsQuery() );
	}

	/**
	 * Resolves one complete terminal address set.
	 *
	 * @param string $host Validated DNS host.
	 * @return list<string> Complete globally usable terminal address set.
	 * @throws ClientMetadataResolutionException When resolution is unsafe or incomplete.
	 */
	public function resolve( string $host ): array {
		$this->reset();
		$this->startedAt = hrtime( true );
		$current         = $host;
		while ( true ) {
			$this->consumeQuery( $current, 'A' );
			$trace = $this->trace( $host );
			$this->consumeQuery( $current, 'AAAA' );
			$trace       = $this->trace( $host );
			$terminalKey = strtolower( $trace['terminal'] );
			$answers     = $this->addresses[ $terminalKey ] ?? array();
			if ( array() !== $answers ) {
				return $this->screen( $answers );
			}
			if ( strtolower( $current ) === $terminalKey ) {
				throw new ClientMetadataResolutionException( 'dns_no_answer' );
			}
			$current = $trace['terminal'];
		}
	}

	/**
	 * Consumes one bounded DNS query result.
	 *
	 * @param string $name Exact DNS name.
	 * @param string $type Exact requested record type.
	 * @throws ClientMetadataResolutionException When the query result is unsafe.
	 */
	private function consumeQuery( string $name, string $type ): void {
		$remaining = self::DEADLINE_MS - $this->elapsedMilliseconds();
		if ( 0 >= $remaining ) {
			throw new ClientMetadataResolutionException( 'dns_deadline' );
		}
		try {
			$messages = ( $this->query )( $name, $type, $remaining );
		} catch ( \Throwable ) {
			throw new ClientMetadataResolutionException( 'dns_malformed' );
		}
		if ( self::DEADLINE_MS < $this->elapsedMilliseconds() || ! is_array( $messages ) || array() === $messages || ! array_is_list( $messages ) ) {
			throw new ClientMetadataResolutionException( 'dns_deadline' );
		}
		foreach ( $messages as $message ) {
			if ( ! is_array( $message ) || self::MAX_MESSAGES < ++$this->messageCount ) {
				throw new ClientMetadataResolutionException( 'dns_message_limit' );
			}
			$bytes = $message['wire_bytes'] ?? null;
			if ( ! is_int( $bytes ) || 0 > $bytes || self::MAX_MESSAGE_BYTES < $bytes ) {
				throw new ClientMetadataResolutionException( 'dns_message_size' );
			}
			$this->wireBytes += $bytes;
			if ( self::MAX_AGGREGATE_BYTES < $this->wireBytes || true === ( $message['malformed'] ?? null ) ) {
				throw new ClientMetadataResolutionException( 'dns_malformed' );
			}
			if ( true === ( $message['truncated'] ?? null ) ) {
				throw new ClientMetadataResolutionException( 'dns_truncated' );
			}
			$status = $message['status'] ?? null;
			if ( ! is_string( $status ) || 'NOERROR' !== $status ) {
				$classification = 'NXDOMAIN' === $status ? 'dns_nxdomain' : ( 'SERVFAIL' === $status ? 'dns_servfail' : 'dns_malformed' );
				throw new ClientMetadataResolutionException( $classification ); // phpcs:ignore WordPress.Security.EscapeOutput.ExceptionNotEscaped -- Sanitized internal classification, not output.
			}
			$records = $message['records'] ?? null;
			if ( ! is_array( $records ) || ! array_is_list( $records ) ) {
				throw new ClientMetadataResolutionException( 'dns_malformed' );
			}
			foreach ( $records as $record ) {
				$this->consumeRecord( $record );
			}
		}
	}

	/**
	 * Consumes one sanitized DNS resource record.
	 *
	 * @param mixed $record Sanitized resource record.
	 * @throws ClientMetadataResolutionException When the record is invalid or exceeds a limit.
	 */
	private function consumeRecord( mixed $record ): void {
		if ( self::MAX_RECORDS < ++$this->recordCount ) {
			throw new ClientMetadataResolutionException( 'dns_record_limit' );
		}
		if ( ! is_array( $record ) || ! is_string( $record['type'] ?? null ) || ! is_string( $record['name'] ?? null ) || ! is_string( $record['value'] ?? null ) ) {
			throw new ClientMetadataResolutionException( 'dns_malformed' );
		}
		$type  = strtoupper( $record['type'] );
		$name  = $record['name'];
		$value = $record['value'];
		if ( 'A' !== $type && 'AAAA' !== $type && 'CNAME' !== $type ) {
			return;
		}
		if ( '' === $name || '' === $value ) {
			throw new ClientMetadataResolutionException( 'dns_malformed' );
		}
		$key = strtolower( rtrim( $name, '.' ) );
		if ( 'CNAME' === $type ) {
			$this->cnameTargets[ $key ][ strtolower( rtrim( $value, '.' ) ) ] = rtrim( $value, '.' );
		} else {
			if ( self::MAX_ADDRESSES < ++$this->addressCount ) {
				throw new ClientMetadataResolutionException( 'dns_address_limit' );
			}
			$this->addresses[ $key ][] = $value;
		}
	}

	/**
	 * Traces one exact, acyclic CNAME chain.
	 *
	 * @param string $host Original DNS host.
	 * @return array{terminal:string} Exact terminal DNS name.
	 * @throws ClientMetadataResolutionException When the chain is unsafe.
	 */
	private function trace( string $host ): array {
		$current = rtrim( $host, '.' );
		$seen    = array( strtolower( $current ) => true );
		$hops    = 0;
		while ( isset( $this->cnameTargets[ strtolower( $current ) ] ) ) {
			$targets = $this->cnameTargets[ strtolower( $current ) ];
			if ( 1 !== count( $targets ) || self::MAX_CNAME_HOPS < ++$hops ) {
				throw new ClientMetadataResolutionException( 'dns_cname_invalid' );
			}
			$current = (string) reset( $targets );
			$key     = strtolower( $current );
			if ( isset( $seen[ $key ] ) ) {
				throw new ClientMetadataResolutionException( 'dns_cname_loop' );
			}
			$seen[ $key ] = true;
		}

		return array( 'terminal' => $current );
	}

	/**
	 * Screens every terminal address and removes exact duplicates.
	 *
	 * @param array $answers Terminal address answers.
	 * @phpstan-param list<string> $answers
	 * @return list<string> Exact unique globally usable addresses.
	 * @throws ClientMetadataResolutionException When any address is unsafe.
	 */
	private function screen( array $answers ): array {
		$unique = array();
		foreach ( $answers as $address ) {
			$packed = inet_pton( $address );
			if ( false === $packed || ! GlobalAddressPolicy::isGloballyUsable( $address ) ) {
				throw new ClientMetadataResolutionException( 'dns_unsafe_address' );
			}
			$unique[ bin2hex( $packed ) ] = $address;
		}

		return array_values( $unique );
	}

	/** Returns elapsed monotonic milliseconds. */
	private function elapsedMilliseconds(): int {
		return (int) floor( ( hrtime( true ) - $this->startedAt ) / 1000000 );
	}

	/** Resets aggregate resolution state. */
	private function reset(): void {
		$this->recordCount  = 0;
		$this->messageCount = 0;
		$this->wireBytes    = 0;
		$this->addressCount = 0;
		$this->cnameTargets = array();
		$this->addresses    = array();
	}
}
