<?php
/**
 * Slice 0 bounded WordPress HTTP fetch tests.
 *
 * @package GalatanOvidiu\Charter
 */

declare(strict_types=1);

namespace GalatanOvidiu\Charter\Tests\Integration\CimdOutboundSafety;

use GalatanOvidiu\Charter\Tests\Prototype\CimdOutboundSafety\BoundFetchResult;
use GalatanOvidiu\Charter\Tests\Prototype\CimdOutboundSafety\BoundWordPressHttpFetcher;
use GalatanOvidiu\Charter\Tests\Prototype\CimdOutboundSafety\ClientIdentifier;
use LogicException;
use PHPUnit\Framework\TestCase;
use RuntimeException;

/**
 * Proves fetch orchestration, hardening, and unconditional scoped cleanup.
 *
 * @since 0.1.0
 */
final class BoundFetchTest extends TestCase {

	/**
	 * Verifies the exact hardening policy and one-dispatch result projection.
	 *
	 * @since 0.1.0
	 */
	public function testFetchesOnceWithTheExactHardeningPolicy(): void {
		$runtime = new RecordingBoundFetchRuntime();
		$fetcher = new BoundWordPressHttpFetcher( $runtime );

		$result = $fetcher->fetch(
			ClientIdentifier::fromString( 'https://client.example/client.json' ),
			array( '8.8.8.8', '2001:4860:4860::8888' )
		);

		self::assertSame( array( 'preflight', 'begin', 'dispatch', 'end' ), $runtime->events );
		self::assertSame( 'complete', $result->classification() );
		self::assertSame( 200, $result->statusCode() );
		self::assertSame( 1, $result->requestCount() );
		self::assertSame( 2, count( $runtime->screenedAddresses ) );
		self::assertSame(
			array(
				'method'                   => 'GET',
				'timeout'                  => 5,
				'connect_timeout'          => 3,
				'redirection'              => 0,
				'sslverify'                => true,
				'blocking'                 => true,
				'decompress'               => false,
				'cookies'                  => array(),
				'body'                     => null,
				'accept'                   => 'application/json',
				'accept_encoding'          => 'identity',
				'cache_control'            => 'no-cache',
				'user_agent'               => 'Charter-CIMD-Proof/1',
				'max_header_bytes'         => 32768,
				'max_header_fields'        => 128,
				'max_header_line_bytes'    => 8192,
				'max_body_bytes'           => 5120,
				'follow_location'          => false,
				'max_redirects'            => 0,
				'fresh_connect'            => true,
				'forbid_reuse'             => true,
				'automatic_content_coding' => false,
			),
			$runtime->policy
		);
	}

	/**
	 * Verifies that unavailable safety controls fail before hooks or dispatch.
	 *
	 * @since 0.1.0
	 */
	public function testFailsBeforeDispatchWhenRuntimePreflightIsUnavailable(): void {
		$runtime                  = new RecordingBoundFetchRuntime();
		$runtime->preflightResult = 'proxy-configured';
		$fetcher                  = new BoundWordPressHttpFetcher( $runtime );

		$result = $fetcher->fetch(
			ClientIdentifier::fromString( 'https://client.example/client.json' ),
			array( '8.8.8.8' )
		);

		self::assertSame( array( 'preflight' ), $runtime->events );
		self::assertSame( 'proxy-configured', $result->classification() );
		self::assertSame( 0, $result->requestCount() );
		self::assertSame( '', $result->body() );
		self::assertSame( array(), $result->headers() );
	}

	/**
	 * Verifies cleanup after a foreign throwable from WordPress dispatch.
	 *
	 * @since 0.1.0
	 */
	public function testAlwaysEndsTheRequestScopeWhenDispatchThrows(): void {
		$runtime                = new RecordingBoundFetchRuntime();
		$runtime->dispatchError = new RuntimeException( 'foreign dispatch failure' );
		$fetcher                = new BoundWordPressHttpFetcher( $runtime );

		try {
			$fetcher->fetch(
				ClientIdentifier::fromString( 'https://client.example/client.json' ),
				array( '8.8.8.8' )
			);
			self::fail( 'Expected the foreign throwable to propagate.' );
		} catch ( RuntimeException $error ) {
			self::assertSame( 'foreign dispatch failure', $error->getMessage() );
		}

		self::assertSame( array( 'preflight', 'begin', 'dispatch', 'end' ), $runtime->events );
	}

	/**
	 * Verifies the result is deliberately not a general serialization surface.
	 *
	 * @since 0.1.0
	 */
	public function testResultCannotBeSerialized(): void {
		$result = RecordingBoundFetchRuntime::completeObservation();

		$this->expectException( LogicException::class );
		// phpcs:ignore WordPress.PHP.DiscouragedPHPFunctions.serialize_serialize -- This proves serialization is rejected.
		serialize( BoundFetchResult::fromObservation( $result ) );
	}
}
