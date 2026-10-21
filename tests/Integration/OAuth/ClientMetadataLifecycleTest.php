<?php
/**
 * Production Client ID Metadata Document lifecycle integration tests.
 *
 * @package GalatanOvidiu\Charter
 */

declare(strict_types=1);

namespace GalatanOvidiu\Charter\Tests\Integration\OAuth;

use GalatanOvidiu\Charter\Http\AuthorizationController;
use GalatanOvidiu\Charter\OAuth\AuthorizationService;
use GalatanOvidiu\Charter\OAuth\ClientMetadataDocumentValidator;
use GalatanOvidiu\Charter\OAuth\ClientMetadataIdentifier;
use GalatanOvidiu\Charter\OAuth\ClientMetadataResolutionException;
use GalatanOvidiu\Charter\OAuth\ClientMetadataResolver;
use GalatanOvidiu\Charter\OAuth\ClientMetadataSnapshotStore;
use GalatanOvidiu\Charter\OAuth\ClientRegistry;
use GalatanOvidiu\Charter\OAuth\ProtocolException;
use GalatanOvidiu\Charter\OAuth\TokenService;
use GalatanOvidiu\Charter\Plugin;
use GalatanOvidiu\Charter\Schema;
use InvalidArgumentException;
use ReflectionMethod;
use WP_UnitTestCase;

/** Exercises authorization-only CIMD onboarding and local credential independence. */
final class ClientMetadataLifecycleTest extends WP_UnitTestCase {

	private const CLIENT_ID    = 'https://metadata.example.test/client.json';
	private const REDIRECT_ONE = 'https://app.example.test/callback';
	private const REDIRECT_TWO = 'http://127.0.0.1:4567/callback';
	private const VERIFIER     = '0123456789abcdefghijklmnopqrstuvwxyzABCDEFG';

	/**
	 * Exact current issuer.
	 *
	 * @var string
	 */
	private string $issuer;

	/**
	 * Represented WordPress user.
	 *
	 * @var int
	 */
	private int $userId;

	/**
	 * Prior direct peer fixture.
	 *
	 * @var mixed
	 */
	private mixed $previousRemoteAddress;

	/** Installs persistent lifecycle tables before Core test transactions. */
	public static function set_up_before_class(): void {
		parent::set_up_before_class();
		Schema::install();
	}

	/** Creates an isolated enabled issuer and persistent OAuth state. */
	public function set_up(): void {
		parent::set_up();
		$plugin = Plugin::boot();
		Schema::install();
		$plugin->credentials()->deleteAll();
		$plugin->clients()->deleteAll();
		$plugin->clientMetadataSnapshots()->deleteAll();
		$plugin->audit()->deleteAll();
		$plugin->rateLimiter()->deleteAll();
		$plugin->siteState()->delete();
		self::assertTrue( $plugin->siteState()->prepareCurrentSite() );
		$identity = $plugin->siteState()->identity();
		self::assertNotNull( $identity );
		$this->issuer = $identity->issuer();
		self::assertTrue( $plugin->siteState()->recordDiscoveryVerification( $this->issuer ) );
		self::assertTrue( $plugin->siteState()->enable( $this->issuer ) );
		$this->userId = self::factory()->user->create( array( 'role' => 'subscriber' ) );
		wp_set_current_user( $this->userId );

		$this->previousRemoteAddress = $_SERVER['REMOTE_ADDR'] ?? null;
		$_SERVER['REMOTE_ADDR']      = '198.51.100.42';
	}

	/** Removes every current-site OAuth fixture. */
	public function tear_down(): void {
		$plugin = Plugin::boot();
		$plugin->credentials()->deleteAll();
		$plugin->clients()->deleteAll();
		$plugin->clientMetadataSnapshots()->deleteAll();
		$plugin->audit()->deleteAll();
		$plugin->rateLimiter()->deleteAll();
		$plugin->siteState()->delete();
		if ( null === $this->previousRemoteAddress ) {
			unset( $_SERVER['REMOTE_ADDR'] );
		} else {
			$_SERVER['REMOTE_ADDR'] = $this->previousRemoteAddress;
		}
		wp_set_current_user( 0 );
		parent::tear_down();
	}

	/** Verifies no-store onboarding supports a complete local refresh lifecycle. */
	public function testNoStoreMetadataNeverPersistsButIssuedCredentialsRemainLocal(): void {
		$fetcher = new SequenceRemoteJsonFetcher(
			array(
				self::response( self::metadataBody( 'Remote client', array( self::REDIRECT_ONE ) ), array( 'cache-control' => array( 'no-store' ) ) ),
			)
		);
		$service = $this->authorization( $fetcher );
		$tokens  = $this->issueTokens( $service, self::REDIRECT_ONE, true );

		self::assertSame( 1, $fetcher->fetchCount() );
		self::assertNull( Plugin::boot()->clientMetadataSnapshots()->findFresh( $this->issuer, self::CLIENT_ID, time() ) );
		$registration = Plugin::boot()->clients()->findRegistration( $this->issuer, self::CLIENT_ID );
		self::assertNotNull( $registration );
		self::assertSame( ClientRegistry::SOURCE_CIMD, $registration->source() );
		self::assertSame( array(), $registration->redirectUris() );
		self::assertArrayHasKey( 'refresh_token', $tokens );

		$rotated = Plugin::boot()->tokens()->exchange(
			array(
				'grant_type'    => 'refresh_token',
				'client_id'     => self::CLIENT_ID,
				'refresh_token' => $tokens['refresh_token'],
			)
		);
		self::assertArrayHasKey( 'refresh_token', $rotated );
		$context = Plugin::boot()->tokens()->validateAccessToken( $rotated['access_token'], $this->issuer, array( AuthorizationService::GENERAL_SCOPE ) );
		self::assertSame( self::CLIENT_ID, $context->clientId() );
		self::assertSame( 1, $fetcher->fetchCount(), 'Token and refresh paths must never fetch remote metadata.' );
	}

	/** Verifies a fresh snapshot rejects unknown redirects without extra egress. */
	public function testFreshSnapshotIsReusedAndDoesNotRefetchForAnAbsentRedirect(): void {
		$fetcher = new SequenceRemoteJsonFetcher(
			array(
				self::response( self::metadataBody( 'Cached client', array( self::REDIRECT_ONE ) ), array( 'cache-control' => array( 'max-age=60' ) ) ),
			)
		);
		$service = $this->authorization( $fetcher );
		$first   = $service->begin( self::authorizationParameters( self::REDIRECT_ONE, false ), $this->userId );
		self::assertNull( $first['reusable_grant_id'] );
		$service->complete( $first['transaction'], $this->userId, true );

		$second = $service->begin( self::authorizationParameters( self::REDIRECT_ONE, false ), $this->userId );
		self::assertIsInt( $second['reusable_grant_id'] );
		self::assertSame( 1, $fetcher->fetchCount() );

		try {
			$service->begin( self::authorizationParameters( self::REDIRECT_TWO, false ), $this->userId );
			self::fail( 'A redirect absent from the fresh snapshot was accepted.' );
		} catch ( ProtocolException $exception ) {
			self::assertSame( 'invalid_request', $exception->error() );
			self::assertNull( $exception->redirectUri() );
		}
		self::assertSame( 1, $fetcher->fetchCount() );
	}

	/** Verifies metadata changes force consent while an origin outage cannot revoke access. */
	public function testMetadataChangeForcesConsentAndOutageDoesNotDisturbExistingAccess(): void {
		$fetcher = new SequenceRemoteJsonFetcher(
			array(
				self::response( self::metadataBody( 'Original client', array( self::REDIRECT_ONE ) ), array( 'cache-control' => array( 'no-cache' ) ) ),
				self::response( self::metadataBody( 'Changed client', array( self::REDIRECT_ONE, self::REDIRECT_TWO ) ), array( 'cache-control' => array( 'no-cache' ) ) ),
				new ClientMetadataResolutionException( 'transport_failed' ),
			)
		);
		$service = $this->authorization( $fetcher );
		$tokens  = $this->issueTokens( $service, self::REDIRECT_ONE, false );

		$changed = $service->begin( self::authorizationParameters( self::REDIRECT_ONE, false ), $this->userId );
		self::assertNull( $changed['reusable_grant_id'], 'Changed user-visible metadata must require fresh consent.' );
		self::assertSame( 2, $fetcher->fetchCount() );
		Plugin::boot()->tokens()->validateAccessToken( $tokens['access_token'], $this->issuer, array( AuthorizationService::GENERAL_SCOPE ) );

		try {
			$service->begin( self::authorizationParameters( self::REDIRECT_ONE, false ), $this->userId );
			self::fail( 'An authorization started without a fresh authoritative document.' );
		} catch ( ProtocolException $exception ) {
			self::assertSame( 'temporarily_unavailable', $exception->error() );
			self::assertSame( 503, $exception->status() );
			self::assertNull( $exception->redirectUri() );
		}
		Plugin::boot()->tokens()->validateAccessToken( $tokens['access_token'], $this->issuer, array( AuthorizationService::GENERAL_SCOPE ) );
		self::assertSame( 3, $fetcher->fetchCount() );
	}

	/** Verifies invalid metadata creates neither lifecycle state nor reusable state. */
	public function testInvalidMetadataFailsBeforeClientLifecyclePersistence(): void {
		$body    = '{"client_id":"' . self::CLIENT_ID . '","client_id":"' . self::CLIENT_ID . '","client_name":"Duplicate","redirect_uris":["' . self::REDIRECT_ONE . '"],"token_endpoint_auth_method":"none"}';
		$fetcher = new SequenceRemoteJsonFetcher( array( self::response( $body, array() ) ) );
		$service = $this->authorization( $fetcher );

		try {
			$service->begin( self::authorizationParameters( self::REDIRECT_ONE, false ), $this->userId );
			self::fail( 'Duplicate security metadata was accepted.' );
		} catch ( ProtocolException $exception ) {
			self::assertSame( 'temporarily_unavailable', $exception->error() );
		}

		self::assertNull( Plugin::boot()->clients()->findRegistration( $this->issuer, self::CLIENT_ID ) );
		self::assertNull( Plugin::boot()->clientMetadataSnapshots()->findFresh( $this->issuer, self::CLIENT_ID, time() ) );
	}

	/** Verifies the strict public-client metadata profile and canonical fingerprint. */
	public function testMetadataValidationRejectsSecurityAmbiguityAndIgnoresEmbeddedUrls(): void {
		$identifier = ClientMetadataIdentifier::fromString( self::CLIENT_ID );
		$first      = ClientMetadataDocumentValidator::validate(
			self::metadataBodyWithOverrides(
				array(
					'redirect_uris' => array( self::REDIRECT_ONE, self::REDIRECT_TWO ),
					'grant_types'   => array( 'authorization_code', 'refresh_token' ),
					'logo_uri'      => 'http://127.0.0.1/private',
					'policy_uri'    => 'https://unrelated.example/policy',
				)
			),
			$identifier
		);
		$reordered  = ClientMetadataDocumentValidator::validate(
			self::metadataBodyWithOverrides(
				array(
					'redirect_uris' => array( self::REDIRECT_TWO, self::REDIRECT_ONE ),
					'grant_types'   => array( 'refresh_token', 'authorization_code' ),
				)
			),
			$identifier
		);
		self::assertSame( $first->fingerprint(), $reordered->fingerprint() );

		$invalidDocuments = array(
			'mismatched client identity' => self::metadataBodyWithOverrides( array( 'client_id' => 'https://other.example/client.json' ) ),
			'confidential method'        => self::metadataBodyWithOverrides( array( 'token_endpoint_auth_method' => 'client_secret_post' ) ),
			'client secret'              => self::metadataBodyWithOverrides( array( 'client_secret' => 'must-not-exist' ) ),
			'private JWK'                => self::metadataBodyWithOverrides(
				array(
					'jwks' => array(
						'keys' => array(
							array(
								'kty' => 'RSA',
								'd'   => 'private',
							),
						),
					),
				)
			),
			'duplicate redirect'         => self::metadataBodyWithOverrides( array( 'redirect_uris' => array( self::REDIRECT_ONE, self::REDIRECT_ONE ) ) ),
			'localhost subdomain'        => self::metadataBodyWithOverrides( array( 'redirect_uris' => array( 'http://app.localhost/callback' ) ) ),
			'localhost suffix'           => self::metadataBodyWithOverrides( array( 'redirect_uris' => array( 'http://localhost.example/callback' ) ) ),
			'unsupported response type'  => self::metadataBodyWithOverrides( array( 'response_types' => array( 'token' ) ) ),
			'unsupported grant type'     => self::metadataBodyWithOverrides( array( 'grant_types' => array( 'authorization_code', 'client_credentials' ) ) ),
			'C0 display control'         => self::metadataBodyWithOverrides( array( 'client_name' => "Unsafe\nclient" ) ),
			'C1 display control'         => self::metadataBodyWithOverrides( array( 'client_name' => "Unsafe\u{0085}client" ) ),
			'bidirectional override'     => self::metadataBodyWithOverrides( array( 'client_name' => "Safe\u{202E}evil" ) ),
			'line separator'             => self::metadataBodyWithOverrides( array( 'client_name' => "Unsafe\u{2028}client" ) ),
		);
		foreach ( $invalidDocuments as $case => $body ) {
			$rejected = false;
			try {
				ClientMetadataDocumentValidator::validate( $body, $identifier );
			} catch ( InvalidArgumentException ) {
				$rejected = true;
			}
			self::assertTrue( $rejected, 'Invalid metadata was accepted: ' . $case );
		}
	}

	/**
	 * Verifies Claude Code's CIMD callbacks accept runtime-selected local ports.
	 */
	public function testAcceptsClaudeCodeCimdAndRuntimeSelectedLocalPorts(): void {
		$clientId   = 'https://claude.ai/oauth/claude-code-client-metadata';
		$identifier = ClientMetadataIdentifier::fromString( $clientId );
		$body       = wp_json_encode(
			array(
				'client_id'                  => $clientId,
				'client_name'                => 'Claude Code',
				'client_uri'                 => 'https://claude.ai',
				'redirect_uris'              => array( 'http://localhost/callback', 'http://127.0.0.1/callback' ),
				'grant_types'                => array( 'authorization_code', 'refresh_token' ),
				'response_types'             => array( 'code' ),
				'token_endpoint_auth_method' => 'none',
			),
			JSON_UNESCAPED_SLASHES
		);
		self::assertIsString( $body );

		$metadata = ClientMetadataDocumentValidator::validate( $body, $identifier );
		$client   = $metadata->client( $this->issuer );
		self::assertSame( array( 'http://localhost/callback', 'http://127.0.0.1/callback' ), $metadata->redirectUris() );
		self::assertTrue( $client->allowsRedirectUri( 'http://localhost:3118/callback' ) );
		self::assertTrue( $client->allowsRedirectUri( 'http://127.0.0.1:3118/callback' ) );
		self::assertFalse( $client->allowsRedirectUri( 'http://localhost:3118/other' ) );
		self::assertFalse( $client->allowsRedirectUri( 'http://localhost:3118/callback?changed=1' ) );
		self::assertFalse( $client->allowsRedirectUri( 'http://[::1]:3118/callback' ) );

		$timestamp = time();
		$snapshots = new ClientMetadataSnapshotStore();
		$snapshots->store( $this->issuer, $metadata, $timestamp, $timestamp + 60 );
		$fresh = $snapshots->findFresh( $this->issuer, $clientId, $timestamp );
		self::assertNotNull( $fresh );
		self::assertSame( $metadata->redirectUris(), $fresh->redirectUris() );
	}

	/** Verifies an expired reusable snapshot is removed before a failed refresh. */
	public function testStaleSnapshotIsNeverAnAuthorizationFallback(): void {
		$plugin     = Plugin::boot();
		$identifier = ClientMetadataIdentifier::fromString( self::CLIENT_ID );
		$metadata   = ClientMetadataDocumentValidator::validate( self::metadataBody( 'Stale client', array( self::REDIRECT_ONE ) ), $identifier );
		$timestamp  = time();
		self::assertTrue( $plugin->clients()->ensureCimdClient( $this->issuer, self::CLIENT_ID, $timestamp ) );
		$plugin->clientMetadataSnapshots()->store( $this->issuer, $metadata, $timestamp, $timestamp + 1 );
		$fetcher  = new SequenceRemoteJsonFetcher( array( new ClientMetadataResolutionException( 'transport_failed' ) ) );
		$resolver = new ClientMetadataResolver( $plugin->clients(), $plugin->clientMetadataSnapshots(), new StaticHostAddressResolver(), $fetcher );

		try {
			$resolver->resolveForAuthorization( $this->issuer, self::CLIENT_ID, $timestamp + 2 );
			self::fail( 'The expired metadata snapshot was used after refresh failure.' );
		} catch ( ClientMetadataResolutionException $exception ) {
			self::assertSame( 'transport_failed', $exception->classification() );
		}
		self::assertNull( $plugin->clientMetadataSnapshots()->findFresh( $this->issuer, self::CLIENT_ID, $timestamp + 2 ) );
		self::assertSame( 1, $fetcher->fetchCount() );
	}

	/** Verifies administrator terminal states prevent later outbound work. */
	public function testBlockingAndDeletionPreventOutboundResolution(): void {
		$fetcher = new SequenceRemoteJsonFetcher(
			array(
				self::response( self::metadataBody( 'Governed client', array( self::REDIRECT_ONE ) ), array( 'cache-control' => array( 'max-age=60' ) ) ),
			)
		);
		$service = $this->authorization( $fetcher );
		$service->begin( self::authorizationParameters( self::REDIRECT_ONE, false ), $this->userId );
		self::assertTrue( Plugin::boot()->clientGovernance()->block( $this->issuer, self::CLIENT_ID, $this->userId, time() ) );

		$this->assertAuthorizationRejectedWithoutFetch( $service, $fetcher );
		self::assertTrue( Plugin::boot()->clientGovernance()->delete( $this->issuer, self::CLIENT_ID, $this->userId, time() ) );
		$this->assertAuthorizationRejectedWithoutFetch( $service, $fetcher );
	}

	/** Verifies represented-user limits stop repeated authorization before egress. */
	public function testAuthorizationRateLimitReturnsRetryAfterBeforeAnotherFetch(): void {
		$fetcher = new SequenceRemoteJsonFetcher(
			array(
				self::response( self::metadataBody( 'Limited client', array( self::REDIRECT_ONE ) ), array( 'cache-control' => array( 'max-age=60' ) ) ),
			)
		);
		$service = $this->authorization( $fetcher );
		$filter  = static fn ( array $policy ): array => array_merge( $policy, array( 'authorization_user_client' => 1 ) );
		add_filter( 'charter_oauth_rate_limit_policy', $filter );
		try {
			$service->begin( self::authorizationParameters( self::REDIRECT_ONE, false ), $this->userId );
			try {
				$service->begin( self::authorizationParameters( self::REDIRECT_ONE, false ), $this->userId );
				self::fail( 'The represented-user authorization limit was not enforced.' );
			} catch ( ProtocolException $exception ) {
				self::assertSame( 429, $exception->status() );
				self::assertIsInt( $exception->retryAfter() );
				self::assertGreaterThan( 0, $exception->retryAfter() );
			}
		} finally {
			remove_filter( 'charter_oauth_rate_limit_policy', $filter );
		}
		self::assertSame( 1, $fetcher->fetchCount() );
	}

	/** Verifies rotating client identifiers cannot bypass the source-address budget. */
	public function testAuthorizationNetworkLimitSpansDifferentClientIdentifiers(): void {
		$secondClientId = 'https://metadata.example.test/second-client.json';
		$fetcher        = new SequenceRemoteJsonFetcher(
			array(
				self::response( self::metadataBody( 'First client', array( self::REDIRECT_ONE ) ), array( 'cache-control' => array( 'no-store' ) ) ),
				self::response( self::metadataBody( 'Second client', array( self::REDIRECT_ONE ), $secondClientId ), array( 'cache-control' => array( 'no-store' ) ) ),
			),
			array( self::CLIENT_ID, $secondClientId )
		);
		$service        = $this->authorization( $fetcher );
		$filter         = static fn ( array $policy ): array => array_merge( $policy, array( 'authorization_network' => 1 ) );
		add_filter( 'charter_oauth_rate_limit_policy', $filter );
		try {
			$service->validate( self::authorizationParameters( self::REDIRECT_ONE, false ) );
			try {
				$service->validate( self::authorizationParameters( self::REDIRECT_ONE, false, $secondClientId ) );
				self::fail( 'A different client identifier bypassed the source-address authorization limit.' );
			} catch ( ProtocolException $exception ) {
				self::assertSame( 429, $exception->status() );
				self::assertIsInt( $exception->retryAfter() );
			}
		} finally {
			remove_filter( 'charter_oauth_rate_limit_policy', $filter );
		}
		self::assertSame( 1, $fetcher->fetchCount() );
	}

	/** A source rejected by its own budget cannot exhaust the issuer budget. */
	public function testRejectedSourceDoesNotConsumeIssuerAuthorizationBudget(): void {
		$secondClientId = 'https://metadata.example.test/issuer-budget-client.json';
		$fetcher        = new SequenceRemoteJsonFetcher(
			array(
				self::response( self::metadataBody( 'First client', array( self::REDIRECT_ONE ) ), array( 'cache-control' => array( 'no-store' ) ) ),
				self::response( self::metadataBody( 'Second client', array( self::REDIRECT_ONE ), $secondClientId ), array( 'cache-control' => array( 'no-store' ) ) ),
			),
			array( self::CLIENT_ID, $secondClientId )
		);
		$service        = $this->authorization( $fetcher );
		$filter         = static fn ( array $policy ): array => array_merge(
			$policy,
			array(
				'authorization_issuer'  => 2,
				'authorization_network' => 1,
			)
		);
		add_filter( 'charter_oauth_rate_limit_policy', $filter );
		try {
			$service->validate( self::authorizationParameters( self::REDIRECT_ONE, false ) );
			try {
				$service->validate( self::authorizationParameters( self::REDIRECT_ONE, false, $secondClientId ) );
				self::fail( 'The exhausted source authorization budget was not enforced.' );
			} catch ( ProtocolException $exception ) {
				self::assertSame( 429, $exception->status() );
			}

			$_SERVER['REMOTE_ADDR'] = '198.51.100.43';
			$service->validate( self::authorizationParameters( self::REDIRECT_ONE, false, $secondClientId ) );
		} finally {
			remove_filter( 'charter_oauth_rate_limit_policy', $filter );
		}
		self::assertSame( 2, $fetcher->fetchCount() );
	}

	/** A fresh metadata snapshot recreates an independently reclaimed client row. */
	public function testFreshSnapshotRecreatesMissingCimdRegistration(): void {
		$fetcher = new SequenceRemoteJsonFetcher(
			array( self::response( self::metadataBody( 'Cached client', array( self::REDIRECT_ONE ) ), array( 'cache-control' => array( 'max-age=60' ) ) ) )
		);
		$service = $this->authorization( $fetcher );
		$service->validate( self::authorizationParameters( self::REDIRECT_ONE, false ) );
		Plugin::boot()->clients()->deleteAll();

		$service->validate( self::authorizationParameters( self::REDIRECT_ONE, false ) );

		self::assertSame( 1, $fetcher->fetchCount() );
		self::assertNotNull( Plugin::boot()->clients()->findActive( $this->issuer, self::CLIENT_ID ) );
	}

	/** Verifies valid logged-out preflight never resolves remote client metadata. */
	public function testAuthorizationPreflightDoesNotFetchClientMetadata(): void {
		$fetcher = new SequenceRemoteJsonFetcher(
			array( self::response( self::metadataBody( 'Remote client', array( self::REDIRECT_ONE ) ), array() ) )
		);

		$this->authorization( $fetcher )->preflight( self::authorizationParameters( self::REDIRECT_ONE, false ) );

		self::assertSame( 0, $fetcher->fetchCount() );
		self::assertNull( Plugin::boot()->clients()->findRegistration( $this->issuer, self::CLIENT_ID ) );
	}

	/** Verifies malformed local parameters fail before any DNS or HTTP boundary. */
	public function testMalformedAuthorizationParametersFailBeforeClientMetadataFetch(): void {
		$fetcher = new SequenceRemoteJsonFetcher(
			array( self::response( self::metadataBody( 'Remote client', array( self::REDIRECT_ONE ) ), array() ) )
		);
		$service = $this->authorization( $fetcher );
		$valid   = self::authorizationParameters( self::REDIRECT_ONE, false );
		$cases   = array(
			'unsupported response type' => array( 'response_type' => 'token' ),
			'unsupported PKCE method'   => array( 'code_challenge_method' => 'plain' ),
			'invalid PKCE challenge'    => array( 'code_challenge' => 'short' ),
			'invalid resource'          => array( 'resource' => 'https://other.example.test' ),
			'invalid scope'             => array( 'scope' => 'unknown:scope' ),
		);
		foreach ( $cases as $case => $overrides ) {
			try {
				$service->validate( array_merge( $valid, $overrides ) );
				self::fail( 'Malformed authorization input reached client metadata resolution: ' . $case );
			} catch ( ProtocolException $exception ) {
				self::assertNull( $exception->redirectUri(), $case );
			}
		}

		self::assertSame( 0, $fetcher->fetchCount() );
	}

	/** Verifies first-use dynamic clients cannot turn local errors into redirects. */
	public function testFirstUseDynamicClientErrorsRemainLocal(): void {
		$fetcher             = new SequenceRemoteJsonFetcher( array() );
		$registration        = Plugin::boot()->clients()->registerDynamicClient(
			$this->issuer,
			'First-use dynamic client',
			array( self::REDIRECT_ONE ),
			'none',
			false,
			time()
		);
		$parameters          = self::authorizationParameters( self::REDIRECT_ONE, false, $registration['client']->clientId() );
		$parameters['scope'] = 'unknown:scope';

		try {
			$this->authorization( $fetcher )->validate( $parameters );
			self::fail( 'A malformed first-use DCR request was accepted.' );
		} catch ( ProtocolException $exception ) {
			self::assertSame( 'invalid_scope', $exception->error() );
			self::assertNull( $exception->redirectUri() );
		}
	}

	/** Verifies operator-managed clients retain safe OAuth error redirects. */
	public function testPreRegisteredClientErrorsRetainValidatedRedirect(): void {
		$fetcher = new SequenceRemoteJsonFetcher( array() );
		self::assertTrue( Plugin::boot()->clients()->registerPublicClient( $this->issuer, 'operator-client', 'Operator client', array( self::REDIRECT_ONE ) ) );
		$parameters                  = self::authorizationParameters( self::REDIRECT_ONE, false, 'operator-client' );
		$parameters['response_type'] = 'token';

		try {
			$this->authorization( $fetcher )->validate( $parameters );
			self::fail( 'An unsupported response type was accepted.' );
		} catch ( ProtocolException $exception ) {
			self::assertSame( 'unsupported_response_type', $exception->error() );
			self::assertSame( self::REDIRECT_ONE, $exception->redirectUri() );
		}
	}

	/** Verifies CIMD consent exposes authoritative origin separately from its name. */
	public function testCimdConsentDisplaysClientIdentifierAndRedirectHostsSeparately(): void {
		$fetcher = new SequenceRemoteJsonFetcher(
			array( self::response( self::metadataBody( 'Friendly remote name', array( self::REDIRECT_ONE ) ), array( 'cache-control' => array( 'no-store' ) ) ) )
		);
		$service = $this->authorization( $fetcher );
		$request = $service->validate( self::authorizationParameters( self::REDIRECT_ONE, false ) );
		$method  = new ReflectionMethod( AuthorizationController::class, 'clientIdentifierProvenanceHtml' );
		$html    = $method->invoke( null, $request );
		self::assertIsString( $html );

		self::assertStringContainsString( '<dt>Client ID host</dt><dd>metadata.example.test</dd>', $html );
		self::assertStringNotContainsString( 'Friendly remote name', $html );
		self::assertStringNotContainsString( 'app.example.test', $html );
	}

	/**
	 * Creates an authorization service with production persistence and injected outbound seams.
	 *
	 * @param SequenceRemoteJsonFetcher $fetcher Deterministic outbound boundary.
	 */
	private function authorization( SequenceRemoteJsonFetcher $fetcher ): AuthorizationService {
		$plugin   = Plugin::boot();
		$resolver = new ClientMetadataResolver( $plugin->clients(), $plugin->clientMetadataSnapshots(), new StaticHostAddressResolver(), $fetcher );

		return new AuthorizationService( $plugin->siteState(), $plugin->clients(), $plugin->credentials(), $resolver, $plugin->rateLimiter(), $plugin->audit(), $plugin->accessPolicy(), $plugin->containment(), $plugin->signingKeys() );
	}

	/**
	 * Issues one complete authorization-code token response.
	 *
	 * @param AuthorizationService $service Authorization service under test.
	 * @param string               $redirectUri Exact redirect URI.
	 * @param bool                 $continuingAccess Whether continuing access is requested.
	 */
	private function issueTokens( AuthorizationService $service, string $redirectUri, bool $continuingAccess ): array {
		$consent  = $service->begin( self::authorizationParameters( $redirectUri, $continuingAccess ), $this->userId );
		$redirect = $service->complete( $consent['transaction'], $this->userId, true );
		$query    = wp_parse_url( $redirect, PHP_URL_QUERY );
		self::assertIsString( $query );
		parse_str( $query, $parameters );
		self::assertIsString( $parameters['code'] ?? null );

		return Plugin::boot()->tokens()->exchange(
			array(
				'grant_type'    => 'authorization_code',
				'client_id'     => self::CLIENT_ID,
				'code'          => $parameters['code'],
				'code_verifier' => self::VERIFIER,
				'redirect_uri'  => $redirectUri,
			)
		);
	}

	/**
	 * Confirms one governed authorization rejection does not invoke transport.
	 *
	 * @param AuthorizationService      $service Authorization service under test.
	 * @param SequenceRemoteJsonFetcher $fetcher Deterministic outbound boundary.
	 */
	private function assertAuthorizationRejectedWithoutFetch( AuthorizationService $service, SequenceRemoteJsonFetcher $fetcher ): void {
		try {
			$service->begin( self::authorizationParameters( self::REDIRECT_ONE, false ), $this->userId );
			self::fail( 'A terminal client lifecycle state allowed authorization.' );
		} catch ( ProtocolException $exception ) {
			self::assertSame( 'invalid_request', $exception->error() );
		}
		self::assertSame( 1, $fetcher->fetchCount() );
	}

	/**
	 * Returns one exact authorization request.
	 *
	 * @param string $redirectUri Exact redirect URI.
	 * @param bool   $continuingAccess Whether continuing access is requested.
	 * @param string $clientId Exact client identifier.
	 */
	private static function authorizationParameters( string $redirectUri, bool $continuingAccess, string $clientId = self::CLIENT_ID ): array {
		return array(
			'response_type'         => 'code',
			'client_id'             => $clientId,
			'redirect_uri'          => $redirectUri,
			'code_challenge'        => TokenService::s256Challenge( self::VERIFIER ),
			'code_challenge_method' => 'S256',
			'scope'                 => $continuingAccess ? AuthorizationService::GENERAL_SCOPE . ' ' . AuthorizationService::OFFLINE_ACCESS_SCOPE : AuthorizationService::GENERAL_SCOPE,
			'state'                 => 'client-state',
		);
	}

	/**
	 * Encodes one authoritative metadata document.
	 *
	 * @param string $name User-facing client name.
	 * @param array  $redirectUris Exact redirect URI set.
	 * @param string $clientId Exact client identifier.
	 */
	private static function metadataBody( string $name, array $redirectUris, string $clientId = self::CLIENT_ID ): string {
		$body = wp_json_encode(
			array(
				'client_id'                  => $clientId,
				'client_name'                => $name,
				'redirect_uris'              => $redirectUris,
				'token_endpoint_auth_method' => 'none',
				'response_types'             => array( 'code' ),
			)
		);
		self::assertIsString( $body );

		return $body;
	}

	/**
	 * Encodes one metadata document with exact test overrides.
	 *
	 * @param array $overrides Metadata member overrides.
	 */
	private static function metadataBodyWithOverrides( array $overrides ): string {
		$body = wp_json_encode(
			array_merge(
				array(
					'client_id'                  => self::CLIENT_ID,
					'client_name'                => 'Remote client',
					'redirect_uris'              => array( self::REDIRECT_ONE ),
					'token_endpoint_auth_method' => 'none',
					'response_types'             => array( 'code' ),
				),
				$overrides
			)
		);
		self::assertIsString( $body );

		return $body;
	}

	/**
	 * Creates one fake complete bounded response.
	 *
	 * @param string $body Complete JSON body.
	 * @param array  $headers Duplicate-preserving response headers.
	 */
	private static function response( string $body, array $headers ): array {
		return array(
			'body'    => $body,
			'headers' => $headers,
		);
	}
}
