<?php
/**
 * Disposable Slice 0 bounded CIMD resolver.
 *
 * @package GalatanOvidiu\Charter
 */

declare(strict_types=1);

namespace GalatanOvidiu\Charter\Tests\Prototype\CimdOutboundSafety;

use Closure;
use InvalidArgumentException;

/**
 * Collects complete scripted DNS answers within fixed proof bounds.
 *
 * @since 0.1.0
 */
final class BoundedResolver {

	private const MAX_CNAME_HOPS           = 8;
	private const MAX_ADDRESSES            = 32;
	private const MAX_RECORDS              = 64;
	private const MAX_MESSAGES             = 16;
	private const MAX_MESSAGE_BYTES        = 16384;
	private const MAX_AGGREGATE_BYTES      = 65536;
	private const MAX_ELAPSED_MILLISECONDS = 1000;

	/**
	 * DNS query boundary.
	 *
	 * @var Closure(string, string, int): array<mixed>
	 */
	private readonly Closure $query;

	/**
	 * Monotonic clock boundary.
	 *
	 * @var Closure(): int
	 */
	private readonly Closure $monotonicMilliseconds;

	/**
	 * Monotonic start time.
	 *
	 * @var int
	 */
	private int $startedAt = 0;

	/**
	 * Logical DNS queries.
	 *
	 * @var int
	 */
	private int $queryCount = 0;

	/**
	 * DNS records observed.
	 *
	 * @var int
	 */
	private int $recordCount = 0;

	/**
	 * DNS messages observed.
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
	 * Terminal address records observed.
	 *
	 * @var int
	 */
	private int $addressCount = 0;

	/**
	 * CNAME targets keyed by case-insensitive owner and target.
	 *
	 * @var array<string, array<string, string>>
	 */
	private array $cnameTargets = array();

	/**
	 * Terminal address spellings keyed by case-insensitive owner.
	 *
	 * @var array<string, list<string>>
	 */
	private array $addressAnswers = array();

	/**
	 * Creates a resolver over proof-owned DNS and clock boundaries.
	 *
	 * @since 0.1.0
	 *
	 * @param callable $query                 DNS query boundary.
	 * @param callable $monotonicMilliseconds Monotonic clock.
	 * @phpstan-param callable(string, string, int): array<mixed> $query
	 * @phpstan-param callable(): int $monotonicMilliseconds
	 */
	public function __construct( callable $query, callable $monotonicMilliseconds ) {
		$this->query                 = Closure::fromCallable( $query );
		$this->monotonicMilliseconds = Closure::fromCallable( $monotonicMilliseconds );
	}

	/**
	 * Resolves one host and returns only bounded, sanitized proof fields.
	 *
	 * @since 0.1.0
	 *
	 * @param string $host Exact DNS host.
	 * @return array{classification:string, addresses:list<string>, cname_chain:list<string>, query_count:int, record_count:int, message_count:int, wire_bytes:int, elapsed_ms:int} Resolution result.
	 */
	public function resolve( string $host ): array {
		$this->reset();
		$this->startedAt = ( $this->monotonicMilliseconds )();

		if ( '' === $host ) {
			return $this->result( 'malformed' );
		}

		$current = $host;

		while ( true ) {
			$failure = $this->consumeQuery( $current, 'A' );
			if ( null !== $failure ) {
				return $this->result( $failure );
			}

			$trace = $this->traceCnameChain( $host );
			if ( null !== $trace['classification'] ) {
				return $this->result( $trace['classification'], $trace['chain'] );
			}

			$failure = $this->consumeQuery( $current, 'AAAA' );
			if ( null !== $failure ) {
				return $this->result( $failure, $trace['chain'] );
			}

			$trace = $this->traceCnameChain( $host );
			if ( null !== $trace['classification'] ) {
				return $this->result( $trace['classification'], $trace['chain'] );
			}

			$terminalKey = strtolower( $trace['terminal'] );
			$addresses   = $this->addressAnswers[ $terminalKey ] ?? array();

			if ( array() !== $addresses ) {
				try {
					$addresses = AddressPolicy::assertGloballyUsableSet( $addresses );
				} catch ( InvalidArgumentException ) {
					return $this->result( 'unsafe_address', $trace['chain'] );
				}

				return $this->result( 'resolved', $trace['chain'], $addresses );
			}

			if ( strtolower( $current ) === $terminalKey ) {
				return $this->result( 'no_answer', $trace['chain'] );
			}

			$current = $trace['terminal'];
		}
	}

	/**
	 * Consumes every bounded message returned by one logical DNS query.
	 *
	 * @param string $name Queried owner name.
	 * @param string $type Queried record type.
	 * @return string|null Stable failure classification, if any.
	 */
	private function consumeQuery( string $name, string $type ): ?string {
		$elapsed = $this->elapsedMilliseconds();
		if ( $elapsed < 0 ) {
			return 'malformed';
		}
		if ( $elapsed >= self::MAX_ELAPSED_MILLISECONDS ) {
			return 'deadline';
		}

		++$this->queryCount;
		$messages = ( $this->query )(
			$name,
			$type,
			self::MAX_ELAPSED_MILLISECONDS - $elapsed
		);

		if ( $this->elapsedMilliseconds() > self::MAX_ELAPSED_MILLISECONDS ) {
			return 'deadline';
		}

		if ( ! array_is_list( $messages ) ) {
			return 'malformed';
		}
		if ( array() === $messages ) {
			return 'deadline';
		}

		foreach ( $messages as $message ) {
			if ( ! is_array( $message ) ) {
				return 'malformed';
			}

			++$this->messageCount;
			if ( $this->messageCount > self::MAX_MESSAGES ) {
				return 'message_limit';
			}

			$wireBytes = $message['wire_bytes'] ?? null;
			if ( ! is_int( $wireBytes ) || $wireBytes < 0 ) {
				return 'malformed';
			}
			if ( $wireBytes > self::MAX_MESSAGE_BYTES ) {
				return 'message_bytes';
			}

			$this->wireBytes += $wireBytes;
			if ( $this->wireBytes > self::MAX_AGGREGATE_BYTES ) {
				return 'aggregate_bytes';
			}

			if ( true === ( $message['malformed'] ?? null ) ) {
				return 'malformed';
			}
			if ( true === ( $message['truncated'] ?? null ) ) {
				return 'truncated';
			}

			$status = $message['status'] ?? null;
			if ( ! is_string( $status ) ) {
				return 'malformed';
			}

			$status = strtoupper( $status );
			if ( 'NXDOMAIN' === $status ) {
				return 'nxdomain';
			}
			if ( 'SERVFAIL' === $status ) {
				return 'servfail';
			}
			if ( 'NOERROR' !== $status ) {
				return 'malformed';
			}

			$records = $message['records'] ?? null;
			if ( ! is_array( $records ) || ! array_is_list( $records ) ) {
				return 'malformed';
			}

			foreach ( $records as $record ) {
				$failure = $this->consumeRecord( $record );
				if ( null !== $failure ) {
					return $failure;
				}
			}
		}

		return null;
	}

	/**
	 * Retains one sanitized DNS record under the aggregate bounds.
	 *
	 * @param mixed $record Candidate sanitized record.
	 * @return string|null Stable failure classification, if any.
	 */
	private function consumeRecord( mixed $record ): ?string {
		++$this->recordCount;
		if ( $this->recordCount > self::MAX_RECORDS ) {
			return 'record_limit';
		}

		if (
			! is_array( $record )
			|| ! is_string( $record['type'] ?? null )
			|| ! is_string( $record['name'] ?? null )
			|| ! is_string( $record['value'] ?? null )
			|| '' === $record['name']
			|| '' === $record['value']
		) {
			return 'malformed';
		}

		$type     = strtoupper( $record['type'] );
		$ownerKey = strtolower( $record['name'] );

		if ( 'CNAME' === $type ) {
			$targetKey = strtolower( $record['value'] );

			$this->cnameTargets[ $ownerKey ][ $targetKey ] = $record['value'];

			return null;
		}

		if ( 'A' !== $type && 'AAAA' !== $type ) {
			return null;
		}

		++$this->addressCount;
		if ( $this->addressCount > self::MAX_ADDRESSES ) {
			return 'address_limit';
		}

		$this->addressAnswers[ $ownerKey ][] = $record['value'];

		return null;
	}

	/**
	 * Follows the currently known CNAME graph from the submitted host.
	 *
	 * @param string $host Original submitted DNS host.
	 * @return array{classification:string|null, terminal:string, chain:list<string>} Current trace.
	 */
	private function traceCnameChain( string $host ): array {
		$current = $host;
		$seen    = array( strtolower( $host ) => true );
		$chain   = array();

		while ( isset( $this->cnameTargets[ strtolower( $current ) ] ) ) {
			$targets = $this->cnameTargets[ strtolower( $current ) ];
			if ( 1 !== count( $targets ) ) {
				return array(
					'classification' => 'malformed',
					'terminal'       => $current,
					'chain'          => $chain,
				);
			}

			$target  = reset( $targets );
			$chain[] = $target;

			if ( count( $chain ) > self::MAX_CNAME_HOPS ) {
				return array(
					'classification' => 'cname_depth',
					'terminal'       => $target,
					'chain'          => $chain,
				);
			}

			$targetKey = strtolower( $target );
			if ( isset( $seen[ $targetKey ] ) ) {
				return array(
					'classification' => 'cname_loop',
					'terminal'       => $target,
					'chain'          => $chain,
				);
			}

			$seen[ $targetKey ] = true;
			$current            = $target;
		}

		return array(
			'classification' => null,
			'terminal'       => $current,
			'chain'          => $chain,
		);
	}

	/**
	 * Produces one fixed-schema result without partial addresses on failure.
	 *
	 * @param string $classification Stable result classification.
	 * @param array  $cnameChain      Traversed CNAME values.
	 * @param array  $addresses       Accepted terminal addresses.
	 * @phpstan-param list<string> $cnameChain
	 * @phpstan-param list<string> $addresses
	 * @return array{classification:string, addresses:list<string>, cname_chain:list<string>, query_count:int, record_count:int, message_count:int, wire_bytes:int, elapsed_ms:int} Resolution result.
	 */
	private function result( string $classification, array $cnameChain = array(), array $addresses = array() ): array {
		return array(
			'classification' => $classification,
			'addresses'      => 'resolved' === $classification ? $addresses : array(),
			'cname_chain'    => $cnameChain,
			'query_count'    => $this->queryCount,
			'record_count'   => $this->recordCount,
			'message_count'  => $this->messageCount,
			'wire_bytes'     => $this->wireBytes,
			'elapsed_ms'     => $this->elapsedMilliseconds(),
		);
	}

	/** Returns elapsed monotonic milliseconds without changing the clock. */
	private function elapsedMilliseconds(): int {
		return ( $this->monotonicMilliseconds )() - $this->startedAt;
	}

	/** Resets all request-local resolver state for process reuse. */
	private function reset(): void {
		$this->queryCount     = 0;
		$this->recordCount    = 0;
		$this->messageCount   = 0;
		$this->wireBytes      = 0;
		$this->addressCount   = 0;
		$this->cnameTargets   = array();
		$this->addressAnswers = array();
	}
}
