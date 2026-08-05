<?php
/**
 * Complete synchronous CIMD validation-boundary tests.
 *
 * @package GalatanOvidiu\Charter
 */

declare(strict_types=1);

namespace GalatanOvidiu\Charter\Tests\Integration\CimdOutboundSafety;

use GalatanOvidiu\Charter\Tests\Prototype\CimdOutboundSafety\AuthorizationBoundary;
use GalatanOvidiu\Charter\Tests\Prototype\CimdOutboundSafety\BoundedResolver;
use GalatanOvidiu\Charter\Tests\Prototype\CimdOutboundSafety\BoundWordPressHttpFetcher;
use GalatanOvidiu\Charter\Tests\Prototype\CimdOutboundSafety\CimdValidationBoundary;
use PHPUnit\Framework\TestCase;

/**
 * Proves resolve-screen-bind-fetch-validate composition before authorization.
 *
 * @since 0.1.0
 */
final class CimdValidationBoundaryTest extends TestCase {

	/**
	 * Verifies a complete synchronous validation and fresh local reuse.
	 */
	public function testComposesEveryOutboundBoundaryBeforeCreatingATransaction(): void {
		$events               = array();
		$resolver             = self::resolver( array( '8.8.8.8' ), $events );
		$runtime              = new RecordingBoundFetchRuntime();
		$runtime->observation = self::observation( self::document() );
		$clock                = static fn (): int => 1000;
		$complete             = new CimdValidationBoundary(
			$resolver,
			new BoundWordPressHttpFetcher( $runtime ),
			$clock
		);
		$boundary             = new AuthorizationBoundary( array( $complete, 'validate' ) );

		$first  = $boundary->authorize( self::clientId(), self::redirect(), 1000 );
		$second = $boundary->authorize( self::clientId(), self::redirect(), 1001 );

		self::assertSame( array( 'dns:A', 'dns:AAAA' ), $events );
		self::assertSame( array( 'preflight', 'begin', 'dispatch', 'end' ), $runtime->events );
		self::assertSame( 'transaction_created', $first['classification'] );
		self::assertSame(
			array(
				'dns'  => 2,
				'tcp'  => 1,
				'tls'  => 1,
				'http' => 1,
			),
			$first['cimd_counters']
		);
		self::assertSame( 'transaction_created', $second['classification'] );
		self::assertSame(
			array(
				'dns'  => 0,
				'tcp'  => 0,
				'tls'  => 0,
				'http' => 0,
			),
			$second['cimd_counters']
		);
	}

	/**
	 * Verifies an unsafe complete answer set stops before fetch dispatch.
	 */
	public function testUnsafeResolutionStopsBeforeBoundFetch(): void {
		$events   = array();
		$resolver = self::resolver( array( '8.8.8.8', '10.0.0.1' ), $events );
		$runtime  = new RecordingBoundFetchRuntime();
		$complete = new CimdValidationBoundary(
			$resolver,
			new BoundWordPressHttpFetcher( $runtime ),
			static fn (): int => 1000
		);

		$result = $complete->validate( self::clientId(), 1000 );

		self::assertSame( 'failed', $result['classification'] );
		self::assertSame( 'dns_unsafe_address', $result['failure_classification'] );
		self::assertSame( array(), $runtime->events );
		self::assertSame(
			array(
				'dns'  => 2,
				'tcp'  => 0,
				'tls'  => 0,
				'http' => 0,
			),
			$result['cimd_counters']
		);
	}

	/**
	 * Creates a bounded resolver whose query seam records exact query order.
	 *
	 * @param string[] $addresses IPv4 terminal answers.
	 * @param array    $events    Event ledger.
	 * @phpstan-param list<string> $addresses
	 * @phpstan-param list<string> $events
	 */
	private static function resolver( array $addresses, array &$events ): BoundedResolver {
		$query = static function ( string $name, string $type, int $remainingMilliseconds ) use ( $addresses, &$events ): array {
			self::assertGreaterThan( 0, $remainingMilliseconds );
			$events[] = 'dns:' . $type;
			$records  = array();
			if ( 'A' === $type ) {
				foreach ( $addresses as $address ) {
					$records[] = array(
						'type'  => 'A',
						'name'  => $name,
						'value' => $address,
					);
				}
			}

			return array(
				array(
					'status'     => 'NOERROR',
					'truncated'  => false,
					'malformed'  => false,
					'wire_bytes' => 64,
					'records'    => $records,
				),
			);
		};

		return new BoundedResolver( $query, static fn (): int => 0 );
	}

	/**
	 * Creates one successful bounded fetch observation.
	 *
	 * @param string $body Complete metadata body.
	 * @return array<string, mixed> Observation.
	 */
	private static function observation( string $body ): array {
		$observation                   = RecordingBoundFetchRuntime::completeObservation();
		$observation['body']           = $body;
		$observation['body_bytes']     = strlen( $body );
		$observation['headers']        = array(
			'content-type'  => array( 'application/json' ),
			'cache-control' => array( 'max-age=300' ),
		);
		$observation['content_coding'] = 'identity';

		return $observation;
	}

	/** Returns one valid metadata document. */
	private static function document(): string {
		return '{"client_id":"' . self::clientId() . '","client_name":"Proof client",'
			. '"redirect_uris":["' . self::redirect() . '"],"token_endpoint_auth_method":"none"}';
	}

	/** Returns the exact proof Client Identifier. */
	private static function clientId(): string {
		return 'https://client.example/metadata';
	}

	/** Returns one exact proof redirect. */
	private static function redirect(): string {
		return 'https://client.example/callback';
	}
}
