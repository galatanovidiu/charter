<?php
/**
 * Slice 0 hostile bounded-fetch integration tests.
 *
 * @package GalatanOvidiu\Charter
 */

declare(strict_types=1);

namespace GalatanOvidiu\Charter\Tests\Integration\CimdOutboundSafety;

use GalatanOvidiu\Charter\Tests\Prototype\CimdOutboundSafety\BoundFetchResult;
use GalatanOvidiu\Charter\Tests\Prototype\CimdOutboundSafety\BoundFetchRuntime;
use GalatanOvidiu\Charter\Tests\Prototype\CimdOutboundSafety\BoundedResolver;
use GalatanOvidiu\Charter\Tests\Prototype\CimdOutboundSafety\BoundWordPressHttpFetcher;
use GalatanOvidiu\Charter\Tests\Prototype\CimdOutboundSafety\CimdValidationBoundary;
use GalatanOvidiu\Charter\Tests\Prototype\CimdOutboundSafety\ClientIdentifier;
use GalatanOvidiu\Charter\Tests\Prototype\CimdOutboundSafety\AuthorizationBoundary;
use PHPUnit\Framework\TestCase;
use WpOrg\Requests\Transport\Fsockopen;

/**
 * Proves that the real WordPress HTTP runtime stays inside the screened peer.
 *
 * @since 0.1.0
 *
 * @group p3-hostile
 */
final class HostileBoundFetchTest extends TestCase {

	/**
	 * Fixed fixture-control counter names.
	 *
	 * @var list<string>
	 */
	private const COUNTER_NAMES = array(
		'dns_query',
		'dns_client_a',
		'dns_client_aaaa',
		'tcp_connection',
		'tls_handshake',
		'http_request',
		'origin_tcp_connection',
		'origin_tls_handshake',
		'origin_http_request',
		'redirect_target',
		'embedded_url',
		'special_tcp_connection',
		'special_tls_handshake',
		'special_http_request',
		'proxy',
		'http_proxy_connection',
		'socks_proxy_connection',
		'credential_path',
		'sensitive_egress',
	);

	/**
	 * Creates one hostile case without serializing WordPress's global hooks.
	 *
	 * @param string|null          $name     Test method name.
	 * @param array<string, mixed> $data     Data-provider values.
	 * @param int|string           $dataName Data-provider case name.
	 */
	public function __construct( ?string $name = null, array $data = array(), $dataName = '' ) {
		parent::__construct( $name, $data, $dataName );
		$this->setPreserveGlobalState( false );
	}

	/**
	 * Skips the hostile group outside its exact WordPress fixture bootstrap.
	 */
	protected function setUp(): void {
		parent::setUp();

		if ( ! defined( 'CHARTER_P3_WORDPRESS_HTTP_BOOTSTRAPPED' ) ) {
			self::markTestSkipped( 'The P3 hostile WordPress HTTP fixture is not bootstrapped.' );
		}

		foreach ( array( 'P3_FIXTURE_CA_FILE', 'P3_FIXTURE_CLIENT_ID', 'P3_FIXTURE_CONTROL_URL' ) as $name ) {
			$value = getenv( $name );
			self::assertIsString( $value, 'A fixed P3 fixture input is unavailable.' );
			self::assertNotSame( '', $value, 'A fixed P3 fixture input is unavailable.' );
		}
	}

	/**
	 * Restores a harmless scenario after every hostile case.
	 */
	protected function tearDown(): void {
		if ( defined( 'CHARTER_P3_WORDPRESS_HTTP_BOOTSTRAPPED' ) ) {
			self::resetScenario( 'safe' );
		}

		parent::tearDown();
	}

	/**
	 * Verifies one accepted, direct, pinned 200 response.
	 */
	public function testAcceptsOneDirectBounded200Response(): void {
		$result   = $this->fetchScenario( 'safe' );
		$counters = self::counters();

		self::assertSame( 'complete', $result->classification() );
		self::assertSame( 200, $result->statusCode() );
		self::assertSame( 1, $result->requestCount() );
		self::assertTrue( $result->peerMatched() );
		self::assertTrue( $result->tlsHostnameVerified() );
		self::assertFalse( $result->redirectFollowed() );
		self::assertSame( 'accepted', $result->mediaClassification() );
		self::assertSame( 'absent', $result->contentCodingClassification() );
		self::assertGreaterThan( 0, $result->bodyBytes() );
		self::assertLessThanOrEqual( 5120, $result->bodyBytes() );
		self::assertSame( 1, $counters['origin_tcp_connection'] );
		self::assertSame( 1, $counters['origin_tls_handshake'] );
		self::assertSame( 1, $counters['origin_http_request'] );
		self::assertNoUnsafeContact( $counters );
	}

	/**
	 * Verifies the candidate can bind and verify one screened IPv6 peer inside
	 * the proof-owned non-egressing network.
	 */
	public function testAcceptsOneDirectBoundedIpv6Response(): void {
		$result   = $this->fetchScenario( 'safe', array( '2001:4860:ffff::34' ) );
		$counters = self::counters();

		self::assertSame( 'complete', $result->classification() );
		self::assertTrue( $result->peerMatched() );
		self::assertTrue( $result->tlsHostnameVerified() );
		self::assertSame( 1, $counters['origin_http_request'] );
		self::assertNoUnsafeContact( $counters );
	}

	/**
	 * Verifies the actual hostile DNS answer is screened, bound, fetched,
	 * validated, cached, and consumed before a transaction is created.
	 */
	public function testCompleteHostileValidationBoundaryPrecedesAuthorization(): void {
		self::resetScenario( 'safe' );
		$boundary = new AuthorizationBoundary( array( $this->completeValidationBoundary(), 'validate' ) );

		$result   = $boundary->authorize(
			self::clientId(),
			'https://app.charter.test/callback',
			time()
		);
		$counters = self::counters();

		self::assertSame( 'transaction_created', $result['classification'] );
		self::assertTrue( $result['snapshot_authoritative'] );
		self::assertSame( 2, $result['cimd_counters']['dns'] );
		self::assertSame( 1, $result['cimd_counters']['http'] );
		self::assertSame( 2, $counters['dns_query'] );
		self::assertSame( 1, $counters['origin_http_request'] );
		self::assertNoUnsafeContact( $counters );
	}

	/**
	 * Verifies one unsafe terminal answer rejects the entire hostile result
	 * before any TCP connection is attempted.
	 */
	public function testCompleteHostileBoundaryRejectsMixedDnsBeforeConnection(): void {
		self::resetScenario( 'dns-mixed' );
		$boundary = new AuthorizationBoundary( array( $this->completeValidationBoundary(), 'validate' ) );

		$result   = $boundary->authorize(
			self::clientId(),
			'https://app.charter.test/callback',
			time()
		);
		$counters = self::counters();

		self::assertSame( 'validation_failed', $result['classification'] );
		self::assertSame( 2, $counters['dns_query'] );
		self::assertSame( 0, $counters['tcp_connection'] );
		self::assertSame( 0, $counters['http_request'] );
		self::assertNoUnsafeContact( $counters );
	}

	/**
	 * Verifies real DNS protocol and CNAME failures stop before transport.
	 *
	 * @dataProvider completeDnsFailureProvider
	 *
	 * @param string $scenario              Fixed hostile DNS scenario.
	 * @param string $expectedFailure        Stable validation failure.
	 * @param int    $expectedDnsQueryCount Exact fixture query count.
	 */
	public function testCompleteHostileBoundaryRejectsDnsFailuresBeforeConnection(
		string $scenario,
		string $expectedFailure,
		int $expectedDnsQueryCount
	): void {
		self::resetScenario( $scenario );

		$result   = $this->completeValidationBoundary()->validate( self::clientId(), time() );
		$counters = self::counters();

		self::assertSame( 'failed', $result['classification'] );
		self::assertSame( $expectedFailure, $result['failure_classification'] );
		self::assertSame( $expectedDnsQueryCount, $counters['dns_query'] );
		self::assertSame( 0, $counters['tcp_connection'] );
		self::assertSame( 0, $counters['http_request'] );
		self::assertNoUnsafeContact( $counters );
	}

	/**
	 * Verifies valid CNAME and full 64-record section packets remain usable.
	 *
	 * @dataProvider completeDnsSuccessProvider
	 *
	 * @param string $scenario              Fixed hostile DNS scenario.
	 * @param int    $expectedDnsQueryCount Exact fixture query count.
	 */
	public function testCompleteHostileBoundaryAcceptsBoundedDnsComposition(
		string $scenario,
		int $expectedDnsQueryCount
	): void {
		self::resetScenario( $scenario );

		$result   = $this->completeValidationBoundary()->validate( self::clientId(), time() );
		$counters = self::counters();

		self::assertSame( 'validated', $result['classification'] );
		self::assertSame( 'none', $result['failure_classification'] );
		self::assertSame( $expectedDnsQueryCount, $counters['dns_query'] );
		self::assertSame( 1, $counters['http_request'] );
		self::assertNoUnsafeContact( $counters );
	}

	/**
	 * Verifies staggered A/AAAA work shares one real one-second deadline.
	 */
	public function testCompleteHostileDnsUsesOneAggregateDeadline(): void {
		self::resetScenario( 'dns-staggered-timeout' );
		$started = hrtime( true );

		$result  = $this->completeValidationBoundary()->validate( self::clientId(), time() );
		$elapsed = (int) ( ( hrtime( true ) - $started ) / 1000000 );

		self::assertSame( 'failed', $result['classification'] );
		self::assertSame( 'dns_deadline', $result['failure_classification'] );
		self::assertLessThanOrEqual( 1150, $elapsed );
		self::assertSame( 2, self::counters()['dns_query'] );
	}

	/**
	 * Verifies a post-screening special or sibling DNS mutation cannot alter the
	 * exact peer set supplied to WordPress cURL.
	 *
	 * @dataProvider postScreenMutationProvider
	 *
	 * @param string $scenario          Fixed mutation scenario.
	 * @param string $mutatedAddress     Exact second-query address.
	 * @param string $forbiddenCounter   Exact negative sink counter.
	 */
	public function testPostScreenDnsMutationCannotChangeTheBoundPeer(
		string $scenario,
		string $mutatedAddress,
		string $forbiddenCounter
	): void {
		self::resetScenario( $scenario );
		$resolution = $this->fixtureResolver()->resolve( ClientIdentifier::fromString( self::clientId() )->host() );

		self::assertSame( 'resolved', $resolution['classification'] );
		self::assertSame( array( '198.17.0.34' ), $resolution['addresses'] );
		$mutation = ( new FixtureDnsQuery( self::dnsServer() ) )(
			'client.charter.test',
			'A',
			1000
		);
		self::assertSame( $mutatedAddress, self::dnsRecordValues( $mutation )[0] ?? null );

		$before   = self::hookCounts();
		$fetcher  = new BoundWordPressHttpFetcher( new BoundFetchRuntime( self::caFile() ) );
		$result   = $fetcher->fetch(
			ClientIdentifier::fromString( self::clientId() ),
			$resolution['addresses']
		);
		$counters = self::counters();

		self::assertSame( 'complete', $result->classification() );
		self::assertSame( 3, $counters['dns_query'] );
		self::assertSame( 1, $counters['origin_http_request'] );
		self::assertSame( 0, $counters[ $forbiddenCounter ] );
		self::assertSame( $before, self::hookCounts() );
	}

	/**
	 * Verifies a reordered complete safe answer set remains exactly screened.
	 */
	public function testSafeAnswerSetReorderingRemainsBoundToTheScreenedSet(): void {
		self::resetScenario( 'dns-safe-reorder' );
		$resolution = $this->fixtureResolver()->resolve( 'client.charter.test' );

		self::assertSame( 'resolved', $resolution['classification'] );
		self::assertSame( array( '198.17.0.34', '2001:4860:ffff::34' ), $resolution['addresses'] );
		$mutation = ( new FixtureDnsQuery( self::dnsServer() ) )( 'client.charter.test', 'A', 1000 );
		self::assertSame(
			array( '2001:4860:ffff::34', '198.17.0.34' ),
			self::dnsRecordValues( $mutation )
		);

		$result   = ( new BoundWordPressHttpFetcher( new BoundFetchRuntime( self::caFile() ) ) )->fetch(
			ClientIdentifier::fromString( self::clientId() ),
			$resolution['addresses']
		);
		$counters = self::counters();

		self::assertSame( 'complete', $result->classification() );
		self::assertSame( 3, $counters['dns_query'] );
		self::assertSame( 1, $counters['origin_http_request'] );
		self::assertNoUnsafeContact( $counters );
	}

	/**
	 * Verifies every structural maximum becomes authoritative and every first
	 * excess or malformed JSON response is rejected after exactly one request.
	 *
	 * @dataProvider hostileMetadataBoundaryProvider
	 *
	 * @param string $scenario               Fixed hostile metadata scenario.
	 * @param string $expectedClassification Validated or failed.
	 */
	public function testCompleteHostileBoundaryEnforcesMetadataStructure(
		string $scenario,
		string $expectedClassification
	): void {
		self::resetScenario( $scenario );

		$result   = $this->completeValidationBoundary()->validate( self::clientId(), time() );
		$counters = self::counters();

		self::assertSame( $expectedClassification, $result['classification'] );
		self::assertSame( 2, $counters['dns_query'] );
		self::assertSame( 1, $counters['origin_http_request'] );
		self::assertNoUnsafeContact( $counters );
	}

	/**
	 * Verifies DNS mutation cannot move a request away from the screened peer.
	 *
	 * @dataProvider dnsMutationProvider
	 *
	 * @param string $scenario Fixed hostile DNS scenario.
	 */
	public function testRetainsTheScreenedPeerWhenFixtureDnsWouldMutate( string $scenario ): void {
		$result   = $this->fetchScenario( $scenario );
		$counters = self::counters();

		self::assertSame( 'complete', $result->classification() );
		self::assertTrue( $result->peerMatched() );
		self::assertTrue( $result->tlsHostnameVerified() );
		self::assertSame( 0, $counters['dns_query'] );
		self::assertSame( 1, $counters['origin_http_request'] );
		self::assertNoUnsafeContact( $counters );
	}

	/**
	 * Verifies original-host TLS validation is mandatory after address binding.
	 */
	public function testRejectsACertificateThatDoesNotNameTheOriginalHost(): void {
		$result   = $this->fetchScenario(
			'safe',
			array( '198.17.0.34' ),
			'https://mismatch.charter.test/client.json'
		);
		$counters = self::counters();

		self::assertSame( 'tls', $result->classification() );
		self::assertSame( 0, $result->requestCount() );
		self::assertFalse( $result->tlsHostnameVerified() );
		self::assertSame( 1, $counters['origin_tcp_connection'] );
		self::assertSame( 1, $counters['origin_tls_handshake'] );
		self::assertSame( 0, $counters['origin_http_request'] );
		self::assertNoUnsafeContact( $counters );
	}

	/**
	 * Verifies redirects are observed once but never followed.
	 *
	 * @dataProvider redirectProvider
	 *
	 * @param string $scenario Fixed redirect scenario.
	 */
	public function testRejectsEveryRedirectWithoutContactingItsTarget( string $scenario ): void {
		$result   = $this->fetchScenario( $scenario );
		$counters = self::counters();

		self::assertSame( 'redirect', $result->classification() );
		self::assertSame( 302, $result->statusCode() );
		self::assertSame( 1, $result->requestCount() );
		self::assertFalse( $result->redirectFollowed() );
		self::assertSame( 1, $counters['origin_http_request'] );
		self::assertSame( 0, $counters['redirect_target'] );
		self::assertNoUnsafeContact( $counters );
	}

	/**
	 * Verifies body boundaries are enforced by the receive callback.
	 *
	 * @dataProvider bodyBoundaryProvider
	 *
	 * @param string $scenario               Fixed body scenario.
	 * @param string $expectedClassification Fixed result classification.
	 */
	public function testEnforcesBodyBoundaries( string $scenario, string $expectedClassification ): void {
		$result   = $this->fetchScenario( $scenario );
		$counters = self::counters();

		self::assertSame( $expectedClassification, $result->classification() );
		self::assertLessThanOrEqual( 5120, $result->bodyBytes() );
		self::assertSame( 1, $result->requestCount() );
		self::assertSame( 1, $counters['origin_http_request'] );
		self::assertNoUnsafeContact( $counters );
	}

	/**
	 * Verifies every status other than 200 is non-authoritative.
	 *
	 * @dataProvider rejectedStatusProvider
	 *
	 * @param string $scenario Fixed response scenario.
	 * @param int    $status   Expected status code.
	 */
	public function testClassifiesEveryNon200Status( string $scenario, int $status ): void {
		$result   = $this->fetchScenario( $scenario );
		$counters = self::counters();

		self::assertSame( 'status', $result->classification() );
		self::assertSame( $status, $result->statusCode() );
		self::assertSame( 1, $result->requestCount() );
		self::assertSame( 1, $counters['origin_http_request'] );
		self::assertNoUnsafeContact( $counters );
	}

	/**
	 * Verifies accepted and rejected JSON media-type classes.
	 *
	 * @dataProvider mediaTypeProvider
	 *
	 * @param string $scenario               Fixed media scenario.
	 * @param string $expectedClassification Fixed fetch classification.
	 * @param string $expectedMedia          Fixed media classification.
	 */
	public function testClassifiesMediaTypes(
		string $scenario,
		string $expectedClassification,
		string $expectedMedia
	): void {
		$result   = $this->fetchScenario( $scenario );
		$counters = self::counters();

		self::assertSame( $expectedClassification, $result->classification() );
		self::assertSame( $expectedMedia, $result->mediaClassification() );
		self::assertSame( 1, $result->requestCount() );
		self::assertSame( 1, $counters['origin_http_request'] );
		self::assertNoUnsafeContact( $counters );
	}

	/**
	 * Verifies compressed responses are rejected without automatic decoding.
	 *
	 * @dataProvider contentCodingProvider
	 *
	 * @param string $scenario Fixed content-coding scenario.
	 */
	public function testRejectsNonIdentityContentCoding( string $scenario ): void {
		$result   = $this->fetchScenario( $scenario );
		$counters = self::counters();

		self::assertSame( 'content-coding', $result->classification() );
		self::assertSame( 1, $result->requestCount() );
		self::assertSame( 1, $counters['origin_http_request'] );
		self::assertNoUnsafeContact( $counters );
	}

	/**
	 * Verifies every exact header/status-line boundary and framing case.
	 *
	 * @dataProvider headerBoundaryProvider
	 *
	 * @param string $scenario               Fixed header scenario.
	 * @param string $expectedClassification Fixed fetch classification.
	 */
	public function testEnforcesHeaderBoundaries( string $scenario, string $expectedClassification ): void {
		$result   = $this->fetchScenario( $scenario );
		$counters = self::counters();

		self::assertSame( $expectedClassification, $result->classification() );
		self::assertLessThanOrEqual( 32768, $result->headerBytes() );
		self::assertLessThanOrEqual( 128, $result->headerFields() );
		self::assertSame( 1, $result->requestCount() );
		self::assertSame( 1, $counters['origin_http_request'] );
		self::assertNoUnsafeContact( $counters );
	}

	/**
	 * Verifies connect, TLS, first-byte, and body deadlines are classified once.
	 *
	 * @dataProvider timeoutProvider
	 *
	 * @param string        $scenario               Fixed delay scenario.
	 * @param array<string> $addresses             Exact screened peer set.
	 * @param string        $expectedClassification Fixed result classification.
	 * @param int           $expectedTcp            Exact total TCP counter.
	 * @param int           $expectedTls            Exact total TLS counter.
	 * @param int           $expectedHttp           Exact total HTTP counter.
	 * @phpstan-param list<string> $addresses
	 */
	public function testClassifiesEachBoundedTimeout(
		string $scenario,
		array $addresses,
		string $expectedClassification,
		int $expectedTcp,
		int $expectedTls,
		int $expectedHttp
	): void {
		$result   = $this->fetchScenario( $scenario, $addresses );
		$counters = self::counters();

		self::assertSame( $expectedClassification, $result->classification() );
		self::assertSame( $expectedTcp, $counters['tcp_connection'] );
		self::assertSame( $expectedTls, $counters['tls_handshake'] );
		self::assertSame( $expectedHttp, $counters['http_request'] );
		self::assertSame( 0, $counters['proxy'] );
		self::assertSame( 0, $counters['sensitive_egress'] );
	}

	/**
	 * Verifies inherited proxy configuration fails before any network dispatch.
	 *
	 * @dataProvider inheritedProxyEnvironmentProvider
	 *
	 * @param string $name Standard proxy environment variable.
	 */
	public function testProxyPreflightRejectsBeforeDispatch( string $name ): void {
		$original = getenv( $name );
		$proxy    = getenv( 'P3_FIXTURE_PROXY_URL' );
		self::assertIsString( $proxy );

		try {
			putenv( $name . '=' . $proxy ); // phpcs:ignore WordPress.PHP.DiscouragedPHPFunctions.runtime_configuration_putenv -- Reversible proof of inherited-proxy fail-closed behavior.
			$result   = $this->fetchScenario( 'safe' );
			$counters = self::counters();

			self::assertSame( 'proxy-configured', $result->classification() );
			self::assertSame( 0, $result->requestCount() );
			self::assertSame( self::zeroCounters(), $counters );
		} finally {
			// phpcs:ignore WordPress.PHP.DiscouragedPHPFunctions.runtime_configuration_putenv -- Restores the exact prior test-process environment.
			false === $original ? putenv( $name ) : putenv( $name . '=' . $original );
		}
	}

	/**
	 * Verifies each HTTP, HTTPS CONNECT, SOCKS local-DNS, and SOCKS remote-DNS
	 * topology is rejected by the candidate before any proxy or origin contact.
	 *
	 * @dataProvider proxyTopologyProvider
	 *
	 * @param string $name     Standard proxy environment variable.
	 * @param string $topology Exact proof topology.
	 * @throws \LogicException For an unknown proof topology.
	 */
	public function testCandidateRejectsEveryProxyTopologyBeforeContact( string $name, string $topology ): void {
		$original = getenv( $name );
		$http     = getenv( 'P3_FIXTURE_PROXY_URL' );
		$socks    = getenv( 'P3_FIXTURE_SOCKS_PROXY_URL' );
		self::assertIsString( $http );
		self::assertIsString( $socks );

		$value = match ( $topology ) {
			'http', 'connect' => $http,
			'socks-local' => 'socks5://' . $socks,
			'socks-remote' => 'socks5h://' . $socks,
			default => throw new \LogicException( 'Unknown proof proxy topology.' ),
		};

		try {
			putenv( $name . '=' . $value ); // phpcs:ignore WordPress.PHP.DiscouragedPHPFunctions.runtime_configuration_putenv -- Reversible hostile proxy topology.
			$result = $this->fetchScenario( 'safe' );

			self::assertSame( 'proxy-configured', $result->classification() );
			self::assertSame( 0, $result->requestCount() );
			self::assertSame( self::zeroCounters(), self::counters() );
		} finally {
			// phpcs:ignore WordPress.PHP.DiscouragedPHPFunctions.runtime_configuration_putenv -- Restores exact prior environment.
			false === $original ? putenv( $name ) : putenv( $name . '=' . $original );
		}
	}

	/**
	 * Verifies a WordPress-configured HTTP/HTTPS CONNECT proxy is rejected before
	 * candidate hooks, DNS, proxy contact, or origin contact.
	 *
	 * @runInSeparateProcess
	 * @preserveGlobalState disabled
	 */
	public function testCandidateRejectsWordPressHttpAndConnectProxyConfiguration(): void {
		define( 'WP_PROXY_HOST', '198.17.0.40' ); // phpcs:ignore WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedConstantFound -- Exact Core proxy configuration.
		define( 'WP_PROXY_PORT', 8080 ); // phpcs:ignore WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedConstantFound -- Exact Core proxy configuration.

		$result = $this->fetchScenario( 'safe' );

		self::assertSame( 'proxy-configured', $result->classification() );
		self::assertSame( 0, $result->requestCount() );
		self::assertSame( self::zeroCounters(), self::counters() );
	}

	/**
	 * Verifies unavailable mandatory capabilities fail before dispatch.
	 */
	public function testCapabilityPreflightRejectsBeforeDispatch(): void {
		self::resetScenario( 'safe' );
		$before  = self::hookCounts();
		$runtime = new class(self::caFile()) extends BoundFetchRuntime {
			/**
			 * Returns one fixed unavailable classification.
			 */
			public function preflight(): string {
				return 'capability-unavailable';
			}
		};
		$fetcher = new BoundWordPressHttpFetcher( $runtime );
		$result  = $fetcher->fetch( ClientIdentifier::fromString( self::clientId() ), array( '198.17.0.34' ) );

		self::assertSame( 'capability-unavailable', $result->classification() );
		self::assertSame( 0, $result->requestCount() );
		self::assertSame( self::zeroCounters(), self::counters() );
		self::assertSame( $before, self::hookCounts() );
	}

	/**
	 * Verifies ambient WordPress argument mutation cannot weaken the request.
	 */
	public function testAmbientRequestArgumentsCannotRestoreUnsafeEgress(): void {
		$mutator = static function ( array $arguments ): array {
			$arguments['redirection'] = 5;
			$arguments['sslverify']   = false;
			$arguments['cookies']     = array( 'not-sent' );
			$arguments['user-agent']  = 'site-bearing-not-sent';
			$arguments['timeout']     = 30;
			return $arguments;
		};
		add_filter( 'http_request_args', $mutator, 1 );

		try {
			$result   = $this->fetchScenario( 'safe' );
			$counters = self::counters();

			self::assertSame( 'complete', $result->classification() );
			self::assertSame( 0, $counters['sensitive_egress'] );
			self::assertSame( 0, $counters['redirect_target'] );
			self::assertSame( 0, $counters['proxy'] );
		} finally {
			remove_filter( 'http_request_args', $mutator, 1 );
		}
	}

	/**
	 * Verifies two sends cannot reuse a stale connection despite process reuse.
	 */
	public function testRepeatedFetchesAlwaysCreateFreshBoundConnections(): void {
		self::resetScenario( 'safe' );
		$before  = self::hookCounts();
		$fetcher = new BoundWordPressHttpFetcher( new BoundFetchRuntime( self::caFile() ) );
		$id      = ClientIdentifier::fromString( self::clientId() );

		$first    = $fetcher->fetch( $id, array( '198.17.0.34' ) );
		$second   = $fetcher->fetch( $id, array( '198.17.0.34' ) );
		$counters = self::counters();

		self::assertSame( 'complete', $first->classification() );
		self::assertSame( 'complete', $second->classification() );
		self::assertSame( 2, $counters['origin_tcp_connection'] );
		self::assertSame( 2, $counters['origin_tls_handshake'] );
		self::assertSame( 2, $counters['origin_http_request'] );
		self::assertSame( $before, self::hookCounts() );
	}

	/**
	 * Verifies an ambient forced-stream selection is replaced with cURL.
	 */
	public function testForcedStreamSelectionIsReplacedWithTheBoundCurlTransport(): void {
		$forceStream = static function (
			string &$url,
			array &$headers,
			mixed &$data,
			string &$type,
			array &$options
		): void {
			unset( $url, $headers, $data, $type );
			$options['transport'] = Fsockopen::class;
		};
		add_action( 'requests-requests.before_request', $forceStream, PHP_INT_MAX - 1, 5 );

		try {
			$result = $this->fetchScenario( 'safe' );

			self::assertSame( 'complete', $result->classification() );
			self::assertSame( 1, self::counters()['origin_http_request'] );
		} finally {
			remove_action( 'requests-requests.before_request', $forceStream, PHP_INT_MAX - 1 );
		}
	}

	/**
	 * Verifies unrelated nested Requests cURL traffic cannot trigger the outer
	 * candidate's post-send exit or leak any outer request hooks.
	 */
	public function testNestedUnrelatedRequestCannotTriggerOuterAfterSend(): void {
		$entered         = false;
		$nestedCompleted = false;
		$nested          = static function ( string &$url ) use ( &$entered, &$nestedCompleted ): void {
			if ( $entered || self::clientId() !== $url ) {
				return;
			}

			$entered         = true;
			$response        = wp_remote_get(
				self::controlUrl() . '/health',
				array(
					'timeout'            => 2,
					'reject_unsafe_urls' => false,
				)
			);
			$nestedCompleted = ! is_wp_error( $response );
		};
		add_action( 'requests-requests.before_request', $nested, PHP_INT_MAX - 1, 1 );

		try {
			$result = $this->fetchScenario( 'safe' );

			self::assertTrue( $entered );
			self::assertTrue( $nestedCompleted );
			self::assertSame( 'complete', $result->classification() );
			self::assertSame( 1, self::counters()['origin_http_request'] );
		} finally {
			remove_action( 'requests-requests.before_request', $nested, PHP_INT_MAX - 1 );
		}
	}

	/**
	 * Provides DNS mutation cases.
	 *
	 * @return array<string, array{string}> Cases.
	 */
	public function dnsMutationProvider(): array {
		return array(
			'public to special rebind' => array( 'dns-rebind' ),
			'public sibling mutation'  => array( 'dns-sibling' ),
		);
	}

	/**
	 * Provides real DNS and packet-adapter failure cases.
	 *
	 * @return array<string, array{string, string, int}> Cases.
	 */
	public function completeDnsFailureProvider(): array {
		return array(
			'NXDOMAIN'             => array( 'dns-nxdomain', 'dns_nxdomain', 1 ),
			'SERVFAIL'             => array( 'dns-servfail', 'dns_servfail', 1 ),
			'timeout'              => array( 'dns-timeout', 'dns_deadline', 1 ),
			'AAAA timeout after A' => array( 'dns-aaaa-timeout', 'dns_deadline', 2 ),
			'malformed packet'     => array( 'dns-malformed', 'dns_malformed', 1 ),
			'truncated packet'     => array( 'dns-truncated', 'dns_truncated', 1 ),
			'CNAME loop'           => array( 'dns-cname-loop', 'dns_cname_loop', 1 ),
			'CNAME to special'     => array( 'dns-cname-special', 'dns_unsafe_address', 4 ),
			'trailing packet data' => array( 'dns-trailing-data', 'dns_malformed', 1 ),
			'65 records'           => array( 'dns-sections-65', 'dns_record_limit', 1 ),
		);
	}

	/**
	 * Provides real bounded DNS success cases.
	 *
	 * @return array<string, array{string, int}> Cases.
	 */
	public function completeDnsSuccessProvider(): array {
		return array(
			'CNAME chain'        => array( 'dns-cname-safe', 4 ),
			'64 section records' => array( 'dns-sections-64', 2 ),
		);
	}

	/**
	 * Provides post-screen special and sibling mutation cases.
	 *
	 * @return array<string, array{string, string, string}> Cases.
	 */
	public function postScreenMutationProvider(): array {
		return array(
			'special rebind'   => array( 'dns-rebind', '198.18.0.10', 'special_tcp_connection' ),
			'sibling mutation' => array( 'dns-sibling', '198.17.0.35', 'redirect_target' ),
		);
	}

	/**
	 * Provides every redirect class exposed by the hostile origin.
	 *
	 * @return array<string, array{string}> Cases.
	 */
	public function redirectProvider(): array {
		return array(
			'public HTTPS'     => array( 'redirect-public' ),
			'loopback address' => array( 'redirect-loopback' ),
			'private address'  => array( 'redirect-private' ),
			'special address'  => array( 'redirect-special' ),
			'HTTP downgrade'   => array( 'redirect-http' ),
			'different port'   => array( 'redirect-port' ),
			'credentials'      => array( 'redirect-credentials' ),
			'malformed'        => array( 'redirect-malformed' ),
			'long'             => array( 'redirect-long' ),
		);
	}

	/**
	 * Provides exact body and framing boundaries.
	 *
	 * @return array<string, array{string, string}> Cases.
	 */
	public function bodyBoundaryProvider(): array {
		return array(
			'5119 bytes'              => array( 'body-5119', 'complete' ),
			'5120 bytes'              => array( 'body-5120', 'complete' ),
			'5121 bytes'              => array( 'body-5121', 'body-bytes' ),
			'chunked overflow'        => array( 'chunked-overflow', 'body-bytes' ),
			'content length overflow' => array( 'content-length-overflow', 'body-bytes' ),
			'early close'             => array( 'early-close', 'truncated' ),
			'valid JSON prefix'       => array( 'valid-json-prefix-truncated', 'truncated' ),
		);
	}

	/**
	 * Provides non-200 response statuses.
	 *
	 * @return array<string, array{string, int}> Cases.
	 */
	public function rejectedStatusProvider(): array {
		return array(
			'status 199' => array( 'status-199', 199 ),
			'status 204' => array( 'status-204', 204 ),
			'status 206' => array( 'status-206', 206 ),
			'status 299' => array( 'status-299', 299 ),
			'status 304' => array( 'status-304', 304 ),
			'status 400' => array( 'status-400', 400 ),
			'status 500' => array( 'status-500', 500 ),
		);
	}

	/**
	 * Provides media-type cases.
	 *
	 * @return array<string, array{string, string, string}> Cases.
	 */
	public function mediaTypeProvider(): array {
		return array(
			'exact JSON'         => array( 'content-type-json', 'complete', 'accepted' ),
			'parameterized JSON' => array( 'content-type-parameterized', 'complete', 'accepted' ),
			'suffix JSON'        => array( 'content-type-suffix-json', 'complete', 'accepted' ),
			'missing'            => array( 'content-type-missing', 'media', 'missing' ),
			'wrong'              => array( 'content-type-wrong', 'media', 'wrong' ),
			'ambiguous'          => array( 'content-type-ambiguous', 'media', 'ambiguous' ),
		);
	}

	/**
	 * Provides unsupported content codings.
	 *
	 * @return array<string, array{string}> Cases.
	 */
	public function contentCodingProvider(): array {
		return array(
			'gzip'   => array( 'encoding-gzip' ),
			'brotli' => array( 'encoding-br' ),
			'other'  => array( 'encoding-deflate' ),
		);
	}

	/**
	 * Provides every exact hostile JSON structure boundary and malformed class.
	 *
	 * @return array<string, array{string, string}> Cases.
	 */
	public function hostileMetadataBoundaryProvider(): array {
		return array(
			'256 nodes'              => array( 'metadata-nodes-256', 'validated' ),
			'257 nodes'              => array( 'metadata-nodes-257', 'failed' ),
			'64 root members'        => array( 'metadata-root-members-64', 'validated' ),
			'65 root members'        => array( 'metadata-root-members-65', 'failed' ),
			'128-byte member name'   => array( 'metadata-member-name-128', 'validated' ),
			'129-byte member name'   => array( 'metadata-member-name-129', 'failed' ),
			'2048-byte string'       => array( 'metadata-string-2048', 'validated' ),
			'2049-byte string'       => array( 'metadata-string-2049', 'failed' ),
			'256-byte client name'   => array( 'metadata-client-name-256', 'validated' ),
			'257-byte client name'   => array( 'metadata-client-name-257', 'failed' ),
			'32 redirects'           => array( 'metadata-redirects-32', 'validated' ),
			'33 redirects'           => array( 'metadata-redirects-33', 'failed' ),
			'2048-byte redirect'     => array( 'metadata-redirect-uri-2048', 'validated' ),
			'2049-byte redirect'     => array( 'metadata-redirect-uri-2049', 'failed' ),
			'depth 16'               => array( 'metadata-depth-16', 'validated' ),
			'depth 17'               => array( 'metadata-depth-17', 'failed' ),
			'invalid UTF-8'          => array( 'metadata-invalid-utf8', 'failed' ),
			'invalid JSON'           => array( 'metadata-invalid-json', 'failed' ),
			'duplicate critical key' => array( 'metadata-duplicate-security', 'failed' ),
			'scalar root'            => array( 'metadata-scalar-root', 'failed' ),
		);
	}

	/**
	 * Provides every standard inherited proxy environment spelling.
	 *
	 * @return array<string, array{string}> Cases.
	 */
	public function inheritedProxyEnvironmentProvider(): array {
		return array(
			'HTTP upper'  => array( 'HTTP_PROXY' ),
			'HTTPS upper' => array( 'HTTPS_PROXY' ),
			'all upper'   => array( 'ALL_PROXY' ),
			'HTTP lower'  => array( 'http_proxy' ),
			'HTTPS lower' => array( 'https_proxy' ),
			'all lower'   => array( 'all_proxy' ),
		);
	}

	/**
	 * Provides the exact configured proxy transport topologies.
	 *
	 * @return array<string, array{string, string}> Cases.
	 */
	public function proxyTopologyProvider(): array {
		return array(
			'HTTP proxy'       => array( 'HTTP_PROXY', 'http' ),
			'HTTPS CONNECT'    => array( 'HTTPS_PROXY', 'connect' ),
			'SOCKS local DNS'  => array( 'ALL_PROXY', 'socks-local' ),
			'SOCKS remote DNS' => array( 'ALL_PROXY', 'socks-remote' ),
		);
	}

	/**
	 * Provides exact status/header-line, field, aggregate, and framing cases.
	 *
	 * @return array<string, array{string, string}> Cases.
	 */
	public function headerBoundaryProvider(): array {
		return array(
			'header line 8191'     => array( 'header-line-8191', 'complete' ),
			'header line 8192'     => array( 'header-line-8192', 'complete' ),
			'header line 8193'     => array( 'header-line-8193', 'header-line' ),
			'status line 8191'     => array( 'status-line-8191', 'complete' ),
			'status line 8192'     => array( 'status-line-8192', 'complete' ),
			'status line 8193'     => array( 'status-line-8193', 'header-line' ),
			'header fields 127'    => array( 'header-fields-127', 'complete' ),
			'header fields 128'    => array( 'header-fields-128', 'complete' ),
			'header fields 129'    => array( 'header-fields-129', 'header-fields' ),
			'header bytes 32767'   => array( 'header-bytes-32767', 'complete' ),
			'header bytes 32768'   => array( 'header-bytes-32768', 'complete' ),
			'header bytes 32769'   => array( 'header-bytes-32769', 'header-bytes' ),
			'interim response'     => array( 'interim-response', 'complete' ),
			'bounded HTTP trailer' => array( 'trailer', 'complete' ),
		);
	}

	/**
	 * Provides timeout phases and their exact fixture counters.
	 *
	 * @return array<string, array{string, list<string>, string, int, int, int}> Cases.
	 */
	public function timeoutProvider(): array {
		return array(
			'connect'    => array( 'safe', array( '198.17.0.250' ), 'timeout', 0, 0, 0 ),
			'TLS'        => array( 'tls-delay', array( '198.17.0.34' ), 'timeout', 1, 0, 0 ),
			'first byte' => array( 'first-byte-delay', array( '198.17.0.34' ), 'timeout', 1, 1, 1 ),
			'slow body'  => array( 'slow-body', array( '198.17.0.34' ), 'timeout', 1, 1, 1 ),
		);
	}

	/**
	 * Creates the real fixture-DNS through WordPress validation composition.
	 */
	private function completeValidationBoundary(): CimdValidationBoundary {
		return new CimdValidationBoundary(
			$this->fixtureResolver(),
			new BoundWordPressHttpFetcher( new BoundFetchRuntime( self::caFile() ) ),
			static fn (): int => time()
		);
	}

	/**
	 * Creates the real fixture-backed resolver with one aggregate clock.
	 */
	private function fixtureResolver(): BoundedResolver {
		$started = hrtime( true );
		return new BoundedResolver(
			new FixtureDnsQuery( self::dnsServer() ),
			static fn (): int => (int) ( ( hrtime( true ) - $started ) / 1000000 )
		);
	}

	/**
	 * Runs one real bound fetch and proves request-scoped hooks are restored.
	 *
	 * @param string        $scenario Fixed hostile fixture scenario.
	 * @param array<string> $addresses Complete screened peer set.
	 * @param string|null   $clientId  Exact Client Identifier override.
	 * @phpstan-param list<string> $addresses
	 */
	private function fetchScenario(
		string $scenario,
		array $addresses = array( '198.17.0.34' ),
		?string $clientId = null
	): BoundFetchResult {
		self::resetScenario( $scenario );
		$before  = self::hookCounts();
		$runtime = new BoundFetchRuntime( self::caFile() );
		$fetcher = new BoundWordPressHttpFetcher( $runtime );

		try {
			return $fetcher->fetch(
				ClientIdentifier::fromString( $clientId ?? self::clientId() ),
				$addresses
			);
		} finally {
			self::assertSame( $before, self::hookCounts(), 'Bound fetch hooks leaked outside the request scope.' );
		}
	}

	/**
	 * Resets one exact fixture scenario and all fixed counters.
	 *
	 * @param string $scenario Fixed scenario name.
	 */
	private static function resetScenario( string $scenario ): void {
		$data = self::control( '/scenario/' . $scenario, 'POST' );

		self::assertSame( 'ready', $data['status'] ?? null );
		self::assertSame( $scenario, $data['scenario'] ?? null );
	}

	/**
	 * Reads only the fixed fixture counters.
	 *
	 * @return array<string, int> Fixed counters.
	 */
	private static function counters(): array {
		$data     = self::control( '/counters' );
		$counters = $data['counters'] ?? null;

		self::assertIsArray( $counters );
		self::assertSame( self::COUNTER_NAMES, array_keys( $counters ) );
		$result = array();
		foreach ( $counters as $name => $value ) {
			if ( ! is_string( $name ) || ! is_int( $value ) || 0 > $value ) {
				self::fail( 'The proof counter response was malformed.' );
			}
			$result[ $name ] = $value;
		}

		return $result;
	}

	/**
	 * Calls the fixed, body-free fixture control protocol.
	 *
	 * @param string $path   Fixed control path.
	 * @param string $method GET or POST.
	 * @return array<string, mixed> Fixed control response.
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
		// phpcs:ignore WordPress.WP.AlternativeFunctions.file_get_contents_file_get_contents -- Exact disposable fixture control request.
		$raw = file_get_contents( $base . $path, false, $context );
		self::assertIsString( $raw, 'The fixed P3 fixture control request failed.' );
		self::assertLessThanOrEqual( 8192, strlen( $raw ) );
		$data = json_decode( $raw, true, 8, JSON_THROW_ON_ERROR );
		self::assertIsArray( $data );
		$result = array();
		foreach ( $data as $name => $value ) {
			if ( ! is_string( $name ) ) {
				self::fail( 'The proof control response was malformed.' );
			}
			$result[ $name ] = $value;
		}

		return $result;
	}

	/**
	 * Returns counts for only the fixed request-scoped hook set.
	 *
	 * @return array<string, int> Hook callback counts.
	 */
	private static function hookCounts(): array {
		global $wp_filter;

		$counts  = array();
		$filters = is_array( $wp_filter ) ? $wp_filter : array();
		foreach (
			array(
				'pre_http_request',
				'http_request_args',
				'https_ssl_verify',
				'requests-requests.before_request',
				'http_api_curl',
				'requests-curl.after_send',
			) as $name
		) {
			$count = 0;
			$hook  = $filters[ $name ] ?? null;
			if ( $hook instanceof \WP_Hook ) {
				foreach ( $hook->callbacks as $callbacks ) {
					$count += is_array( $callbacks ) ? count( $callbacks ) : 0;
				}
			}
			$counts[ $name ] = $count;
		}

		return $counts;
	}

	/**
	 * Extracts the exact first-message record values from a fixture DNS reply.
	 *
	 * @param list<array<string, mixed>> $messages Sanitized fixture DNS messages.
	 * @return list<string> Exact record values.
	 */
	private static function dnsRecordValues( array $messages ): array {
		$message = $messages[0] ?? null;
		$records = is_array( $message ) ? ( $message['records'] ?? null ) : null;
		if ( ! is_array( $records ) || ! array_is_list( $records ) ) {
			self::fail( 'The proof DNS response did not contain a record list.' );
		}

		$values = array();
		foreach ( $records as $record ) {
			$value = is_array( $record ) ? ( $record['value'] ?? null ) : null;
			if ( ! is_string( $value ) ) {
				self::fail( 'The proof DNS response contained a malformed record.' );
			}
			$values[] = $value;
		}

		return $values;
	}

	/**
	 * Asserts no negative sink, proxy, or secret-policy counter changed.
	 *
	 * @param array<string, int> $counters Fixed counters.
	 */
	private static function assertNoUnsafeContact( array $counters ): void {
		foreach (
			array(
				'redirect_target',
				'embedded_url',
				'special_tcp_connection',
				'special_tls_handshake',
				'special_http_request',
				'proxy',
				'http_proxy_connection',
				'socks_proxy_connection',
				'sensitive_egress',
			) as $name
		) {
			self::assertSame( 0, $counters[ $name ], 'An unsafe fixed counter changed: ' . $name );
		}
	}

	/**
	 * Returns the complete fixed zero-counter set.
	 *
	 * @return array<string, int> Zero counters.
	 */
	private static function zeroCounters(): array {
		return array_fill_keys( self::COUNTER_NAMES, 0 );
	}

	/**
	 * Returns the exact fixture Client Identifier.
	 */
	private static function clientId(): string {
		$value = getenv( 'P3_FIXTURE_CLIENT_ID' );
		self::assertIsString( $value );
		return $value;
	}

	/**
	 * Returns the exact fixture control origin without exposing environment.
	 */
	private static function controlUrl(): string {
		$value = getenv( 'P3_FIXTURE_CONTROL_URL' );
		self::assertIsString( $value );
		return $value;
	}

	/**
	 * Returns the exact proof DNS fixture endpoint.
	 */
	private static function dnsServer(): string {
		$value = getenv( 'P3_FIXTURE_DNS_SERVER' );
		self::assertIsString( $value );
		return $value;
	}

	/**
	 * Returns the disposable proof CA path.
	 */
	private static function caFile(): string {
		$value = getenv( 'P3_FIXTURE_CA_FILE' );
		self::assertIsString( $value );
		return $value;
	}
}
