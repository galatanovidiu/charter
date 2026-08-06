<?php
/**
 * Production CIMD transport hostile-network integration tests.
 *
 * @package GalatanOvidiu\Charter
 */

declare(strict_types=1);

namespace GalatanOvidiu\Charter\Tests\Integration\CimdOutboundSafety;

use GalatanOvidiu\Charter\Http\BoundedDirectJsonFetcher;
use GalatanOvidiu\Charter\OAuth\ClientMetadataDocumentValidator;
use GalatanOvidiu\Charter\OAuth\ClientMetadataIdentifier;
use GalatanOvidiu\Charter\OAuth\ClientMetadataResolutionException;
use GalatanOvidiu\Charter\Security\BoundedHostResolver;
use JsonException;
use PHPUnit\Framework\TestCase;

// Fixed non-egressing fixture control has no WordPress filesystem abstraction.
// phpcs:disable WordPress.WP.AlternativeFunctions.file_get_contents_file_get_contents

/**
 * Verifies the production direct cURL and complete DNS boundaries against hostile fixtures.
 *
 * @group p3-hostile
 */
final class ProductionCimdTransportTest extends TestCase {

	/**
	 * Creates one hostile case without serializing WordPress's global hooks.
	 *
	 * @param string|null          $name Test method name.
	 * @param array<string, mixed> $data Data-provider values.
	 * @param int|string           $dataName Data-provider case name.
	 */
	public function __construct( ?string $name = null, array $data = array(), $dataName = '' ) {
		parent::__construct( $name, $data, $dataName );
		$this->setPreserveGlobalState( false );
	}

	/** Skips outside the exact hostile WordPress fixture bootstrap. */
	protected function setUp(): void {
		parent::setUp();
		if ( ! defined( 'CHARTER_P3_WORDPRESS_HTTP_BOOTSTRAPPED' ) ) {
			self::markTestSkipped( 'The hostile WordPress HTTP fixture is not bootstrapped.' );
		}
		foreach ( array( 'P3_FIXTURE_CA_FILE', 'P3_FIXTURE_CLIENT_ID', 'P3_FIXTURE_CONTROL_URL', 'P3_FIXTURE_DNS_SERVER' ) as $name ) {
			$value = getenv( $name );
			self::assertIsString( $value );
			self::assertNotSame( '', $value );
		}
	}

	/** Restores a harmless fixture scenario after every production case. */
	protected function tearDown(): void {
		if ( defined( 'CHARTER_P3_WORDPRESS_HTTP_BOOTSTRAPPED' ) ) {
			self::resetScenario( 'safe' );
		}
		parent::tearDown();
	}

	/** Verifies full production DNS, peer binding, TLS, JSON, and metadata validation. */
	public function testProductionBoundaryAcceptsOneAuthoritativeDocument(): void {
		self::resetScenario( 'safe' );
		$identifier = ClientMetadataIdentifier::fromString( self::clientId() );
		$addresses  = ( new BoundedHostResolver() )->resolve( $identifier->host() );
		$response   = ( new BoundedDirectJsonFetcher( self::caFile() ) )->fetch( $identifier, $addresses );
		$metadata   = ClientMetadataDocumentValidator::validate( $response->body(), $identifier );
		$counters   = self::counters();

		self::assertSame( array( '198.17.0.34' ), $addresses );
		self::assertSame( self::clientId(), $metadata->clientId() );
		self::assertSame( 2, $counters['dns_query'] ?? null );
		self::assertSame( 1, $counters['origin_tcp_connection'] ?? null );
		self::assertSame( 1, $counters['origin_tls_handshake'] ?? null );
		self::assertSame( 1, $counters['origin_http_request'] ?? null );
		self::assertNoUnsafeContact( $counters );
	}

	/** Verifies one unsafe DNS answer prevents every transport connection. */
	public function testProductionResolverRejectsMixedAnswersBeforeTransport(): void {
		self::resetScenario( 'dns-mixed' );
		$fetcher = new BoundedDirectJsonFetcher( self::caFile() );
		$fetcher->assertAvailable();

		try {
			self::resolver()->resolve( ClientMetadataIdentifier::fromString( self::clientId() )->host() );
			self::fail( 'The mixed terminal answer set was accepted.' );
		} catch ( ClientMetadataResolutionException $exception ) {
			self::assertSame( 'dns_unsafe_address', $exception->classification() );
		}
		$counters = self::counters();
		self::assertSame( 2, $counters['dns_query'] ?? null );
		self::assertSame( 0, $counters['tcp_connection'] ?? null );
		self::assertSame( 0, $counters['http_request'] ?? null );
		self::assertNoUnsafeContact( $counters );
	}

	/** Verifies post-screen DNS mutation cannot move the production connection. */
	public function testProductionFetchRemainsBoundDuringDnsRebinding(): void {
		self::resetScenario( 'dns-rebind' );
		$identifier = ClientMetadataIdentifier::fromString( self::clientId() );
		$addresses  = self::resolver()->resolve( $identifier->host() );
		$response   = ( new BoundedDirectJsonFetcher( self::caFile() ) )->fetch( $identifier, $addresses );
		$counters   = self::counters();

		self::assertNotSame( '', $response->body() );
		self::assertSame( array( '198.17.0.34' ), $addresses );
		self::assertSame( 2, $counters['dns_query'] ?? null );
		self::assertSame( 1, $counters['origin_http_request'] ?? null );
		self::assertSame( 0, $counters['special_tcp_connection'] ?? null );
		self::assertNoUnsafeContact( $counters );
	}

	/** Verifies inherited proxy configuration fails before DNS or transport. */
	public function testProductionPreflightRejectsProxyBeforeDns(): void {
		self::resetScenario( 'safe' );
		$previous = getenv( 'HTTPS_PROXY' );
		putenv( 'HTTPS_PROXY=http://198.17.0.40:8080' ); // phpcs:ignore WordPress.PHP.DiscouragedPHPFunctions.runtime_configuration_putenv -- Exact inherited proxy preflight fixture.
		try {
			try {
				( new BoundedDirectJsonFetcher( self::caFile() ) )->assertAvailable();
				self::fail( 'Inherited proxy configuration was accepted.' );
			} catch ( ClientMetadataResolutionException $exception ) {
				self::assertSame( 'proxy_configured', $exception->classification() );
			}
		} finally {
			false === $previous
				? putenv( 'HTTPS_PROXY' ) // phpcs:ignore WordPress.PHP.DiscouragedPHPFunctions.runtime_configuration_putenv -- Restores inherited test process state.
				: putenv( 'HTTPS_PROXY=' . $previous ); // phpcs:ignore WordPress.PHP.DiscouragedPHPFunctions.runtime_configuration_putenv -- Restores inherited test process state.
		}

		self::assertSame( self::zeroContactCounters(), self::contactCounters( self::counters() ) );
	}

	/**
	 * Verifies redirect and over-limit body responses fail after exactly one origin request.
	 *
	 * @dataProvider rejectedResponseProvider
	 *
	 * @param string $scenario Fixed hostile response scenario.
	 * @param string $classification Expected production failure class.
	 */
	public function testProductionFetchRejectsUnsafeResponses( string $scenario, string $classification ): void {
		self::resetScenario( $scenario );
		$identifier = ClientMetadataIdentifier::fromString( self::clientId() );
		try {
			( new BoundedDirectJsonFetcher( self::caFile() ) )->fetch( $identifier, array( '198.17.0.34' ) );
			self::fail( 'An unsafe response was accepted: ' . $scenario );
		} catch ( ClientMetadataResolutionException $exception ) {
			self::assertSame( $classification, $exception->classification() );
		}
		$counters = self::counters();
		self::assertSame( 1, $counters['origin_http_request'] ?? null );
		self::assertSame( 0, $counters['redirect_target'] ?? null );
		self::assertNoUnsafeContact( $counters );
	}

	/** Returns selected rejected hostile response scenarios. */
	public function rejectedResponseProvider(): iterable {
		yield 'redirect' => array( 'redirect-public', 'redirect_rejected' );
		yield 'body over limit' => array( 'body-5121', 'body_limit' );
		yield 'compressed coding' => array( 'encoding-gzip', 'coding_rejected' );
	}

	/** Creates the production resolver over the bounded fixture DNS packet seam. */
	private static function resolver(): BoundedHostResolver {
		return new BoundedHostResolver( new FixtureDnsQuery( self::dnsServer() ) );
	}

	/**
	 * Resets one exact fixture scenario and all counters.
	 *
	 * @param string $scenario Fixed fixture scenario.
	 */
	private static function resetScenario( string $scenario ): void {
		$data = self::control( '/scenario/' . $scenario, 'POST' );
		self::assertSame( 'ready', $data['status'] ?? null );
		self::assertSame( $scenario, $data['scenario'] ?? null );
	}

	/** Returns fixed fixture counters. */
	private static function counters(): array {
		$data = self::control( '/counters' );
		self::assertIsArray( $data['counters'] ?? null );

		return $data['counters'];
	}

	/**
	 * Calls the fixed body-free fixture control protocol.
	 *
	 * @param string $path Fixed control path.
	 * @param string $method HTTP method.
	 */
	private static function control( string $path, string $method = 'GET' ): array {
		$base = getenv( 'P3_FIXTURE_CONTROL_URL' );
		self::assertIsString( $base );
		self::assertSame( 1, preg_match( '#^/[a-z0-9/-]+$#D', $path ) );
		$context = stream_context_create(
			array(
				'http' => array(
					'method'        => $method,
					'timeout'       => 2,
					'ignore_errors' => true,
					'header'        => "Connection: close\r\n",
				),
			)
		);
		$raw     = file_get_contents( $base . $path, false, $context );
		self::assertIsString( $raw );
		self::assertLessThanOrEqual( 8192, strlen( $raw ) );
		try {
			$data = json_decode( $raw, true, 8, JSON_THROW_ON_ERROR );
		} catch ( JsonException ) {
			self::fail( 'The fixed fixture control response was not JSON.' );
		}
		self::assertIsArray( $data );

		return $data;
	}

	/**
	 * Verifies no unsafe fixture sink was contacted.
	 *
	 * @param array $counters Fixed fixture counters.
	 */
	private static function assertNoUnsafeContact( array $counters ): void {
		foreach ( array( 'redirect_target', 'embedded_url', 'special_tcp_connection', 'special_tls_handshake', 'special_http_request', 'proxy', 'http_proxy_connection', 'socks_proxy_connection', 'credential_path', 'sensitive_egress' ) as $name ) {
			self::assertSame( 0, $counters[ $name ] ?? null, $name );
		}
	}

	/**
	 * Returns counters proving preflight had no DNS or transport effect.
	 *
	 * @param array $counters Fixed fixture counters.
	 */
	private static function contactCounters( array $counters ): array {
		$result = array();
		foreach ( array_keys( self::zeroContactCounters() ) as $name ) {
			$result[ $name ] = $counters[ $name ] ?? null;
		}

		return $result;
	}

	/** Returns the exact zero-contact counter projection. */
	private static function zeroContactCounters(): array {
		return array(
			'dns_query'           => 0,
			'tcp_connection'      => 0,
			'tls_handshake'       => 0,
			'http_request'        => 0,
			'origin_http_request' => 0,
			'proxy'               => 0,
		);
	}

	/** Returns the exact fixture Client Identifier. */
	private static function clientId(): string {
		$value = getenv( 'P3_FIXTURE_CLIENT_ID' );
		self::assertIsString( $value );

		return $value;
	}

	/** Returns the exact fixture DNS endpoint. */
	private static function dnsServer(): string {
		$value = getenv( 'P3_FIXTURE_DNS_SERVER' );
		self::assertIsString( $value );

		return $value;
	}

	/** Returns the exact fixture certificate authority path. */
	private static function caFile(): string {
		$value = getenv( 'P3_FIXTURE_CA_FILE' );
		self::assertIsString( $value );

		return $value;
	}
}
