<?php
/**
 * Slice 0 CIMD bounded-resolver tests.
 *
 * @package GalatanOvidiu\Charter
 */

declare(strict_types=1);

namespace GalatanOvidiu\Charter\Tests\Integration\CimdOutboundSafety;

use GalatanOvidiu\Charter\Tests\Prototype\CimdOutboundSafety\BoundedResolver;
use LogicException;
use PHPUnit\Framework\TestCase;

/**
 * Proves complete A/AAAA/CNAME collection under every exact resolver bound.
 *
 * @since 0.1.0
 */
final class BoundedResolverTest extends TestCase {

	/**
	 * Verifies that all terminal A and AAAA answers are returned and counted.
	 *
	 * @since 0.1.0
	 */
	public function testCollectsTheCompleteTerminalAddressSet(): void {
		$resolver = self::resolver(
			array(
				'client.example|A'    => array(
					self::exchange(
						array(
							self::message(
								array(
									self::record( 'A', 'client.example', '8.8.8.8' ),
									self::record( 'A', 'client.example', '1.1.1.1' ),
								),
								120
							),
						),
						100
					),
				),
				'client.example|AAAA' => array(
					self::exchange(
						array(
							self::message(
								array(
									self::record( 'AAAA', 'client.example', '2001:4860:4860::8888' ),
									self::record( 'AAAA', 'client.example', '2606:4700:4700::1111' ),
								),
								140
							),
						),
						150
					),
				),
			)
		);

		$result = $resolver->resolve( 'client.example' );

		self::assertSame( 'resolved', $result['classification'] );
		self::assertSame(
			array( '8.8.8.8', '1.1.1.1', '2001:4860:4860::8888', '2606:4700:4700::1111' ),
			$result['addresses']
		);
		self::assertSame( array(), $result['cname_chain'] );
		self::assertSame( 2, $result['query_count'] );
		self::assertSame( 4, $result['record_count'] );
		self::assertSame( 2, $result['message_count'] );
		self::assertSame( 260, $result['wire_bytes'] );
		self::assertSame( 250, $result['elapsed_ms'] );
	}

	/**
	 * Verifies that one unsafe answer rejects every otherwise safe answer.
	 *
	 * @since 0.1.0
	 */
	public function testRejectsACompleteMixedAnswerSetWithoutReturningPartialAddresses(): void {
		$resolver = self::resolver(
			self::terminalScript(
				array( '8.8.8.8', '1.1.1.1' ),
				array( '2001:4860:4860::8888', 'fe80::1' )
			)
		);

		$result = $resolver->resolve( 'client.example' );

		self::assertSame( 'unsafe_address', $result['classification'] );
		self::assertSame( array(), $result['addresses'] );
		self::assertSame( 4, $result['record_count'] );
	}

	/**
	 * Verifies a complete CNAME chain followed by terminal A and AAAA answers.
	 *
	 * @since 0.1.0
	 */
	public function testTraversesAndReturnsOneCompleteCnameChain(): void {
		$resolver = self::resolver(
			array(
				'client.example|A'    => array(
					self::exchange(
						array( self::message( array( self::record( 'CNAME', 'client.example', 'edge.example' ) ) ) )
					),
				),
				'client.example|AAAA' => array(
					self::exchange(
						array( self::message( array( self::record( 'CNAME', 'client.example', 'edge.example' ) ) ) )
					),
				),
				'edge.example|A'      => array(
					self::exchange(
						array( self::message( array( self::record( 'A', 'edge.example', '8.8.4.4' ) ) ) )
					),
				),
				'edge.example|AAAA'   => array(
					self::exchange(
						array( self::message( array( self::record( 'AAAA', 'edge.example', '2001:4860:4860::8844' ) ) ) )
					),
				),
			)
		);

		$result = $resolver->resolve( 'client.example' );

		self::assertSame( 'resolved', $result['classification'] );
		self::assertSame( array( 'edge.example' ), $result['cname_chain'] );
		self::assertSame( array( '8.8.4.4', '2001:4860:4860::8844' ), $result['addresses'] );
		self::assertSame( 4, $result['query_count'] );
		self::assertSame( 4, $result['record_count'] );
	}

	/**
	 * Verifies equivalent duplicate terminal answers are deduplicated.
	 *
	 * @since 0.1.0
	 */
	public function testDeduplicatesTerminalAnswersByBinaryAddress(): void {
		$resolver = self::resolver(
			self::terminalScript(
				array( '8.8.8.8', '8.8.8.8' ),
				array( '2001:4860:4860::8888', '2001:4860:4860:0:0:0:0:8888' )
			)
		);

		$result = $resolver->resolve( 'client.example' );

		self::assertSame( 'resolved', $result['classification'] );
		self::assertSame( array( '8.8.8.8', '2001:4860:4860::8888' ), $result['addresses'] );
		self::assertSame( 4, $result['record_count'] );
	}

	/**
	 * Verifies deterministic DNS-protocol failure classifications.
	 *
	 * @since 0.1.0
	 *
	 * @dataProvider dnsFailureProvider
	 *
	 * @param string               $expectedClassification Stable failure classification.
	 * @param array<string, mixed> $firstMessage           First DNS message.
	 */
	public function testFailsClosedOnDnsProtocolFailure(
		string $expectedClassification,
		array $firstMessage
	): void {
		$resolver = self::resolver(
			array(
				'client.example|A' => array( self::exchange( array( $firstMessage ) ) ),
			)
		);

		$result = $resolver->resolve( 'client.example' );

		self::assertSame( $expectedClassification, $result['classification'] );
		self::assertSame( array(), $result['addresses'] );
	}

	/**
	 * Verifies that successful empty A and AAAA responses are not success.
	 *
	 * @since 0.1.0
	 */
	public function testFailsClosedWhenBothTerminalAnswerSetsAreEmpty(): void {
		$resolver = self::resolver(
			array(
				'client.example|A'    => array( self::exchange( array( self::message() ) ) ),
				'client.example|AAAA' => array( self::exchange( array( self::message() ) ) ),
			)
		);

		$result = $resolver->resolve( 'client.example' );

		self::assertSame( 'no_answer', $result['classification'] );
		self::assertSame( array(), $result['addresses'] );
	}

	/**
	 * Verifies deterministic rejection of CNAME loops.
	 *
	 * @since 0.1.0
	 */
	public function testRejectsCnameLoopsWithoutReturningAnAddress(): void {
		$resolver = self::resolver(
			array(
				'client.example|A'    => array(
					self::exchange(
						array( self::message( array( self::record( 'CNAME', 'client.example', 'edge.example' ) ) ) )
					),
				),
				'client.example|AAAA' => array(
					self::exchange(
						array( self::message( array( self::record( 'CNAME', 'client.example', 'edge.example' ) ) ) )
					),
				),
				'edge.example|A'      => array(
					self::exchange(
						array( self::message( array( self::record( 'CNAME', 'edge.example', 'client.example' ) ) ) )
					),
				),
			)
		);

		$result = $resolver->resolve( 'client.example' );

		self::assertSame( 'cname_loop', $result['classification'] );
		self::assertSame( array(), $result['addresses'] );
	}

	/**
	 * Verifies the exact eight-hop CNAME boundary and first excess.
	 *
	 * @since 0.1.0
	 *
	 * @dataProvider cnameDepthProvider
	 *
	 * @param int    $hops                   CNAME hop count.
	 * @param string $expectedClassification Expected result.
	 */
	public function testEnforcesTheExactCnameDepthBound( int $hops, string $expectedClassification ): void {
		$records = array();

		for ( $hop = 0; $hop < $hops; ++$hop ) {
			$records[] = self::record( 'CNAME', 'name' . $hop . '.example', 'name' . ( $hop + 1 ) . '.example' );
		}

		$records[] = self::record( 'A', 'name' . $hops . '.example', '8.8.8.8' );

		$resolver = self::resolver(
			array(
				'name0.example|A'    => array( self::exchange( array( self::message( $records ) ) ) ),
				'name0.example|AAAA' => array( self::exchange( array( self::message() ) ) ),
			)
		);

		$result = $resolver->resolve( 'name0.example' );

		self::assertSame( $expectedClassification, $result['classification'] );
		self::assertSame( 'resolved' === $expectedClassification ? array( '8.8.8.8' ) : array(), $result['addresses'] );
	}

	/**
	 * Verifies the exact terminal-address count boundary and first excess.
	 *
	 * @since 0.1.0
	 *
	 * @dataProvider addressCountProvider
	 *
	 * @param int    $count                  Terminal address count.
	 * @param string $expectedClassification Expected result.
	 */
	public function testEnforcesTheExactTerminalAddressBound( int $count, string $expectedClassification ): void {
		$addresses = array();

		for ( $index = 1; $index <= $count; ++$index ) {
			$addresses[] = '8.0.0.' . $index;
		}

		$result = self::resolver( self::terminalScript( $addresses ) )->resolve( 'client.example' );

		self::assertSame( $expectedClassification, $result['classification'] );
		self::assertSame( 'resolved' === $expectedClassification ? $count : 0, count( $result['addresses'] ) );
	}

	/**
	 * Verifies the exact total-record count boundary and first excess.
	 *
	 * @since 0.1.0
	 *
	 * @dataProvider recordCountProvider
	 *
	 * @param int    $count                  DNS record count.
	 * @param string $expectedClassification Expected result.
	 */
	public function testEnforcesTheExactRecordBound( int $count, string $expectedClassification ): void {
		$records = array( self::record( 'A', 'client.example', '8.8.8.8' ) );

		for ( $index = 1; $index < $count; ++$index ) {
			$records[] = self::record( 'TXT', 'client.example', 'bounded-' . $index );
		}

		$result = self::resolver(
			array(
				'client.example|A'    => array( self::exchange( array( self::message( $records ) ) ) ),
				'client.example|AAAA' => array( self::exchange( array( self::message() ) ) ),
			)
		)->resolve( 'client.example' );

		self::assertSame( $expectedClassification, $result['classification'] );
		self::assertSame( 'resolved' === $expectedClassification ? array( '8.8.8.8' ) : array(), $result['addresses'] );
	}

	/**
	 * Verifies the exact DNS-message count boundary and first excess.
	 *
	 * @since 0.1.0
	 *
	 * @dataProvider messageCountProvider
	 *
	 * @param int    $count                  DNS message count.
	 * @param string $expectedClassification Expected result.
	 */
	public function testEnforcesTheExactMessageBound( int $count, string $expectedClassification ): void {
		$aMessages = array( self::message( array( self::record( 'A', 'client.example', '8.8.8.8' ) ) ) );

		for ( $index = 2; $index < $count; ++$index ) {
			$aMessages[] = self::message();
		}

		$result = self::resolver(
			array(
				'client.example|A'    => array( self::exchange( $aMessages ) ),
				'client.example|AAAA' => array( self::exchange( array( self::message() ) ) ),
			)
		)->resolve( 'client.example' );

		self::assertSame( $expectedClassification, $result['classification'] );
		self::assertSame( 'resolved' === $expectedClassification ? array( '8.8.8.8' ) : array(), $result['addresses'] );
	}

	/**
	 * Verifies the exact per-message wire-byte bound and first excess.
	 *
	 * @since 0.1.0
	 *
	 * @dataProvider messageByteProvider
	 *
	 * @param int    $wireBytes              Message size.
	 * @param string $expectedClassification Expected result.
	 */
	public function testEnforcesTheExactPerMessageByteBound( int $wireBytes, string $expectedClassification ): void {
		$result = self::resolver(
			array(
				'client.example|A'    => array(
					self::exchange(
						array( self::message( array( self::record( 'A', 'client.example', '8.8.8.8' ) ), $wireBytes ) )
					),
				),
				'client.example|AAAA' => array( self::exchange( array( self::message( array(), 1 ) ) ) ),
			)
		)->resolve( 'client.example' );

		self::assertSame( $expectedClassification, $result['classification'] );
		self::assertSame( 'resolved' === $expectedClassification ? array( '8.8.8.8' ) : array(), $result['addresses'] );
	}

	/**
	 * Verifies the exact aggregate DNS wire-byte bound and first excess.
	 *
	 * @since 0.1.0
	 *
	 * @dataProvider aggregateByteProvider
	 *
	 * @param int    $finalMessageBytes       Last message size.
	 * @param string $expectedClassification Expected result.
	 */
	public function testEnforcesTheExactAggregateByteBound(
		int $finalMessageBytes,
		string $expectedClassification
	): void {
		$result = self::resolver(
			array(
				'client.example|A'    => array(
					self::exchange(
						array(
							self::message( array( self::record( 'A', 'client.example', '8.8.8.8' ) ), 16384 ),
							self::message( array(), 16384 ),
							self::message( array(), 16384 ),
						)
					),
				),
				'client.example|AAAA' => array(
					self::exchange( array( self::message( array(), 16384 ), self::message( array(), $finalMessageBytes ) ) ),
				),
			)
		)->resolve( 'client.example' );

		self::assertSame( $expectedClassification, $result['classification'] );
		self::assertSame( 'resolved' === $expectedClassification ? array( '8.8.8.8' ) : array(), $result['addresses'] );
	}

	/**
	 * Verifies the exact aggregate one-second deadline and first excess.
	 *
	 * @since 0.1.0
	 *
	 * @dataProvider deadlineProvider
	 *
	 * @param int    $elapsedMilliseconds    Aggregate elapsed time.
	 * @param string $expectedClassification Expected result.
	 */
	public function testEnforcesTheExactAggregateDeadline(
		int $elapsedMilliseconds,
		string $expectedClassification
	): void {
		$aDelay    = intdiv( $elapsedMilliseconds, 2 );
		$aaaaDelay = $elapsedMilliseconds - $aDelay;
		$script    = array(
			'client.example|A'    => array(
				self::exchange(
					array( self::message( array( self::record( 'A', 'client.example', '8.8.8.8' ) ) ) ),
					$aDelay
				),
			),
			'client.example|AAAA' => array(
				self::exchange( array( self::message() ), $aaaaDelay ),
			),
		);

		$result = self::resolver( $script )->resolve( 'client.example' );

		self::assertSame( $expectedClassification, $result['classification'] );
		self::assertSame( $elapsedMilliseconds, $result['elapsed_ms'] );
		self::assertSame( 'resolved' === $expectedClassification ? array( '8.8.8.8' ) : array(), $result['addresses'] );
	}

	/**
	 * Verifies every physical query receives only the remaining aggregate budget.
	 */
	public function testPassesOnlyTheRemainingAggregateDeadlineToEachQuery(): void {
		$elapsed  = 0;
		$budgets  = array();
		$query    = static function ( string $name, string $type, int $remainingMilliseconds ) use ( &$elapsed, &$budgets ): array {
			$budgets[] = $remainingMilliseconds;
			$elapsed  += 'A' === $type ? 600 : 401;
			$records   = 'A' === $type
				? array( self::record( 'A', $name, '8.8.8.8' ) )
				: array();

			return array( self::message( $records ) );
		};
		$clock    = static function () use ( &$elapsed ): int {
			return $elapsed;
		};
		$resolver = new BoundedResolver( $query, $clock );

		$result = $resolver->resolve( 'client.example' );

		self::assertSame( array( 1000, 400 ), $budgets );
		self::assertSame( 'deadline', $result['classification'] );
		self::assertSame( 1001, $result['elapsed_ms'] );
	}

	/**
	 * Verifies a physical A or AAAA query that returns no DNS message cannot be
	 * mistaken for a complete empty answer set.
	 */
	public function testRejectsAnEmptyPhysicalDnsReply(): void {
		$result = self::resolver(
			array(
				'client.example|A'    => array(
					self::exchange(
						array( self::message( array( self::record( 'A', 'client.example', '8.8.8.8' ) ) ) )
					),
				),
				'client.example|AAAA' => array( self::exchange( array() ) ),
			)
		)->resolve( 'client.example' );

		self::assertSame( 'deadline', $result['classification'] );
		self::assertSame( array(), $result['addresses'] );
		self::assertSame( 2, $result['query_count'] );
	}

	/**
	 * Provides deterministic DNS protocol failures.
	 *
	 * @since 0.1.0
	 *
	 * @return iterable<string, array{string, array<string, mixed>}> Failures.
	 */
	public function dnsFailureProvider(): iterable {
		yield 'NXDOMAIN' => array( 'nxdomain', self::message( array(), 64, 'NXDOMAIN' ) );
		yield 'SERVFAIL' => array( 'servfail', self::message( array(), 64, 'SERVFAIL' ) );
		yield 'malformed' => array( 'malformed', self::message( array(), 64, 'NOERROR', false, true ) );
		yield 'truncated' => array( 'truncated', self::message( array(), 64, 'NOERROR', true ) );
	}

	/**
	 * Provides exact CNAME depth boundaries.
	 *
	 * @return iterable<string, array{int, string}> Cases.
	 */
	public function cnameDepthProvider(): iterable {
		yield 'eight hops' => array( 8, 'resolved' );
		yield 'first excess' => array( 9, 'cname_depth' );
	}

	/**
	 * Provides exact address-count boundaries.
	 *
	 * @return iterable<string, array{int, string}> Cases.
	 */
	public function addressCountProvider(): iterable {
		yield 'thirty-two addresses' => array( 32, 'resolved' );
		yield 'first excess' => array( 33, 'address_limit' );
	}

	/**
	 * Provides exact record-count boundaries.
	 *
	 * @return iterable<string, array{int, string}> Cases.
	 */
	public function recordCountProvider(): iterable {
		yield 'sixty-four records' => array( 64, 'resolved' );
		yield 'first excess' => array( 65, 'record_limit' );
	}

	/**
	 * Provides exact DNS-message-count boundaries.
	 *
	 * @return iterable<string, array{int, string}> Cases.
	 */
	public function messageCountProvider(): iterable {
		yield 'sixteen messages' => array( 16, 'resolved' );
		yield 'first excess' => array( 17, 'message_limit' );
	}

	/**
	 * Provides exact per-message byte boundaries.
	 *
	 * @return iterable<string, array{int, string}> Cases.
	 */
	public function messageByteProvider(): iterable {
		yield 'sixteen KiB' => array( 16384, 'resolved' );
		yield 'first excess' => array( 16385, 'message_bytes' );
	}

	/**
	 * Provides exact aggregate byte boundaries.
	 *
	 * @return iterable<string, array{int, string}> Cases.
	 */
	public function aggregateByteProvider(): iterable {
		yield 'sixty-four KiB' => array( 0, 'resolved' );
		yield 'first excess' => array( 1, 'aggregate_bytes' );
	}

	/**
	 * Provides exact deadline boundaries.
	 *
	 * @return iterable<string, array{int, string}> Cases.
	 */
	public function deadlineProvider(): iterable {
		yield 'one millisecond below' => array( 999, 'resolved' );
		yield 'exactly one second' => array( 1000, 'resolved' );
		yield 'first excess' => array( 1001, 'deadline' );
	}

	/**
	 * Creates a resolver driven only by injected messages and monotonic time.
	 *
	 * @param array<string, list<array{advance_ms:int, messages:list<array<string, mixed>>}>> $script Query script.
	 * @return BoundedResolver Resolver.
	 */
	private static function resolver( array $script ): BoundedResolver {
		$now = 0;

		$query = static function ( string $name, string $type, int $remainingMilliseconds ) use ( &$script, &$now ): array {
			if ( $remainingMilliseconds <= 0 || 1000 < $remainingMilliseconds ) {
				throw new LogicException( 'The resolver supplied an invalid remaining deadline.' );
			}
			$key = strtolower( $name ) . '|' . strtoupper( $type );

			if ( ! isset( $script[ $key ][0] ) ) {
				throw new LogicException( 'The resolver made an unexpected DNS query.' );
			}

			$exchange = array_shift( $script[ $key ] );
			$now     += $exchange['advance_ms'];

			return $exchange['messages'];
		};

		$clock = static function () use ( &$now ): int {
			return $now;
		};

		return new BoundedResolver( $query, $clock );
	}

	/**
	 * Creates direct terminal A/AAAA query scripts.
	 *
	 * @param array $ipv4Addresses IPv4 answers.
	 * @param array $ipv6Addresses IPv6 answers.
	 * @phpstan-param list<string> $ipv4Addresses
	 * @phpstan-param list<string> $ipv6Addresses
	 * @return array<string, list<array{advance_ms:int, messages:list<array<string, mixed>>}>> Script.
	 */
	private static function terminalScript( array $ipv4Addresses, array $ipv6Addresses = array() ): array {
		$ipv4Records = array();
		$ipv6Records = array();

		foreach ( $ipv4Addresses as $address ) {
			$ipv4Records[] = self::record( 'A', 'client.example', $address );
		}

		foreach ( $ipv6Addresses as $address ) {
			$ipv6Records[] = self::record( 'AAAA', 'client.example', $address );
		}

		return array(
			'client.example|A'    => array( self::exchange( array( self::message( $ipv4Records ) ) ) ),
			'client.example|AAAA' => array( self::exchange( array( self::message( $ipv6Records ) ) ) ),
		);
	}

	/**
	 * Creates one logical query exchange containing one or more DNS messages.
	 *
	 * @param list<array<string, mixed>> $messages  DNS messages.
	 * @param int                        $advanceMs Monotonic time consumed.
	 * @return array{advance_ms:int, messages:list<array<string, mixed>>} Exchange.
	 */
	private static function exchange( array $messages, int $advanceMs = 0 ): array {
		return array(
			'advance_ms' => $advanceMs,
			'messages'   => $messages,
		);
	}

	/**
	 * Creates one bounded sanitized DNS message.
	 *
	 * @param list<array{type:string, name:string, value:string}> $records   DNS records.
	 * @param int                                                 $wireBytes Message wire size.
	 * @param string                                              $status    DNS status.
	 * @param bool                                                $truncated Whether truncation was signaled.
	 * @param bool                                                $malformed Whether parsing failed.
	 * @return array<string, mixed> DNS message.
	 */
	private static function message(
		array $records = array(),
		int $wireBytes = 64,
		string $status = 'NOERROR',
		bool $truncated = false,
		bool $malformed = false
	): array {
		return array(
			'status'     => $status,
			'truncated'  => $truncated,
			'malformed'  => $malformed,
			'wire_bytes' => $wireBytes,
			'records'    => $records,
		);
	}

	/**
	 * Creates one bounded sanitized DNS record.
	 *
	 * @param string $type  Record type.
	 * @param string $name  Owner name.
	 * @param string $value Record value.
	 * @return array{type:string, name:string, value:string} DNS record.
	 */
	private static function record( string $type, string $name, string $value ): array {
		return array(
			'type'  => $type,
			'name'  => $name,
			'value' => $value,
		);
	}
}
