<?php
/**
 * First working OAuth path integration tests.
 *
 * @package GalatanOvidiu\Charter
 */

declare(strict_types=1);

namespace GalatanOvidiu\Charter\Tests\Integration\OAuth;

use GalatanOvidiu\Charter\Http\EndpointUrls;
use GalatanOvidiu\Charter\OAuth\AccessPolicy;
use GalatanOvidiu\Charter\OAuth\AuthorizationService;
use GalatanOvidiu\Charter\OAuth\Client;
use GalatanOvidiu\Charter\OAuth\CredentialStore;
use GalatanOvidiu\Charter\OAuth\DynamicRegistrationService;
use GalatanOvidiu\Charter\OAuth\EmergencyContainment;
use GalatanOvidiu\Charter\OAuth\ProtocolException;
use GalatanOvidiu\Charter\OAuth\TokenService;
use GalatanOvidiu\Charter\OAuth\TransactionManager;
use GalatanOvidiu\Charter\Plugin;
use GalatanOvidiu\Charter\Rest\ProtectedRoute;
use GalatanOvidiu\Charter\Schema;
use GalatanOvidiu\Charter\Security\AuditWriter;
use WP_Application_Passwords;
use WP_REST_Request;
use WP_REST_Server;
use WP_UnitTestCase;

/**
 * Exercises discovery, Authorization Code, S256 PKCE, and REST protection.
 *
 * @since 0.1.0
 */
final class FirstOAuthPathTest extends WP_UnitTestCase {

	private const CLIENT_ID                   = 'charter-integration-client';
	private const REDIRECT_URI                = 'https://client.example.test/callback';
	private const VERIFIER                    = '0123456789abcdefghijklmnopqrstuvwxyzABCDEFG';
	private const CONFIDENTIAL_CLIENT_ID      = 'charter-confidential-client';
	private const CONFIDENTIAL_REDIRECT_URI   = 'https://backend.example.test/callback';
	private const PUBLIC_REFRESH_CLIENT_ID    = 'charter-public-refresh-client';
	private const PUBLIC_REFRESH_REDIRECT_URI = 'http://127.0.0.1:4000/callback';
	private const MCP_CLIENT_ID               = 'charter-mcp-profile-client';
	private const MCP_REDIRECT_URI            = 'https://mcp-client.example.test/callback';
	private const MCP_SCOPE                   = 'example-mcp:access';
	private const MCP_MANAGE_SCOPE            = 'example-mcp:manage';

	/**
	 * Whether the simulated MCP integration provides its registrations.
	 *
	 * @var bool
	 */
	private bool $mcpProviderAvailable = true;

	/**
	 * Test WordPress REST server.
	 *
	 * @var WP_REST_Server
	 */
	private WP_REST_Server $server;

	/**
	 * Represented WordPress user.
	 *
	 * @var int
	 */
	private int $userId;

	/**
	 * Exact issuer under test.
	 *
	 * @var string
	 */
	private string $issuer;

	/**
	 * Installs persistent lifecycle tables before Core starts per-test transactions.
	 *
	 * The production lifecycle intentionally uses an independent database
	 * connection, so temporary tables owned by Core's test transaction are not
	 * an accurate integration boundary.
	 *
	 * @since 0.1.0
	 */
	public static function set_up_before_class(): void {
		parent::set_up_before_class();
		Schema::install();
	}

	/**
	 * Creates isolated current-site OAuth state and REST routes.
	 *
	 * @since 0.1.0
	 */
	public function set_up(): void {
		parent::set_up();

		$plugin = Plugin::boot();
		Schema::install();
		$plugin->credentials()->deleteAll();
		$plugin->clients()->deleteAll();
		$plugin->clientMetadataSnapshots()->deleteAll();
		$plugin->audit()->deleteAll();
		$plugin->rateLimiter()->deleteAll();
		$plugin->containment()->delete();
		self::assertTrue( DynamicRegistrationService::setEnabled( true ) );
		$plugin->siteState()->delete();
		self::assertTrue( $plugin->siteState()->prepareCurrentSite() );

		$identity = $plugin->siteState()->identity();
		self::assertNotNull( $identity );
		$this->issuer = $identity->issuer();
		self::assertTrue(
			$plugin->clients()->registerPublicClient(
				$this->issuer,
				self::CLIENT_ID,
				'Charter integration client',
				array( self::REDIRECT_URI )
			)
		);
		self::assertTrue(
			$plugin->clients()->registerPublicClient(
				$this->issuer,
				self::MCP_CLIENT_ID,
				'Example MCP client',
				array( self::MCP_REDIRECT_URI ),
				true
			)
		);
		$this->mcpProviderAvailable = true;
		add_action( 'charter_oauth_register_access', array( $this, 'registerMcpAccess' ), 10, 2 );

		$this->userId = self::factory()->user->create( array( 'role' => 'subscriber' ) );
		wp_set_current_user( 0 );

		add_action( 'rest_api_init', array( $this, 'registerTestRoutes' ), 20 );
		global $wp_rest_server; // phpcs:ignore WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedVariableFound -- Core-owned REST server global.
		$wp_rest_server = new WP_REST_Server(); // phpcs:ignore WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedVariableFound -- Assigns the Core-owned REST server global.
		do_action( 'rest_api_init', $wp_rest_server ); // phpcs:ignore WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedHooknameFound -- Executes the Core-owned registration hook in the isolated test server.
		$this->server = $wp_rest_server;
	}

	/**
	 * Removes all current-site test OAuth state.
	 *
	 * @since 0.1.0
	 */
	public function tear_down(): void {
		remove_action( 'rest_api_init', array( $this, 'registerTestRoutes' ), 20 );
		remove_action( 'charter_oauth_register_access', array( $this, 'registerMcpAccess' ), 10 );
		$plugin = Plugin::boot();
		$plugin->credentials()->deleteAll();
		$plugin->clients()->deleteAll();
		$plugin->clientMetadataSnapshots()->deleteAll();
		$plugin->audit()->deleteAll();
		$plugin->rateLimiter()->deleteAll();
		$plugin->containment()->delete();
		DynamicRegistrationService::setEnabled( true );
		$plugin->siteState()->delete();
		wp_set_current_user( 0 );
		unset( $_SERVER['PHP_AUTH_USER'], $_SERVER['PHP_AUTH_PW'] );
		$GLOBALS['wp_rest_application_password_status'] = null; // phpcs:ignore WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedVariableFound -- Resets Core authentication test state.

		parent::tear_down();
	}

	/**
	 * Verifies Available, Prepared, and Enabled publication/operation boundaries.
	 *
	 * @since 0.1.0
	 */
	public function testLifecyclePublishesTruthfulMetadataBeforeExactEnablement(): void {
		$plugin = Plugin::boot();
		$plugin->siteState()->delete();

		$missing = $this->dispatch( 'GET', '/charter/v1/metadata/authorization-server' );
		self::assertSame( 404, $missing->get_status() );
		self::assertTrue( $plugin->siteState()->prepareCurrentSite() );

		$prepared = $this->dispatch( 'GET', '/charter/v1/metadata/authorization-server' );
		self::assertSame( 200, $prepared->get_status() );
		self::assertSame( $this->issuer, $prepared->get_data()['issuer'] );
		self::assertArrayNotHasKey( 'authorization_endpoint', $prepared->get_data() );
		self::assertArrayNotHasKey( 'token_endpoint', $prepared->get_data() );
		self::assertArrayNotHasKey( 'grant_types_supported', $prepared->get_data() );
		self::assertSame( '*', $prepared->get_headers()['Access-Control-Allow-Origin'] );

		$resource = $this->dispatch( 'GET', '/charter/v1/metadata/protected-resource' );
		self::assertSame( $this->issuer, $resource->get_data()['resource'] );
		self::assertArrayNotHasKey( 'authorization_servers', $resource->get_data() );

		try {
			$plugin->authorization()->validate( $this->authorizationParameters() );
			self::fail( 'Prepared issuers must not execute authorization.' );
		} catch ( ProtocolException $exception ) {
			self::assertSame( 'temporarily_unavailable', $exception->error() );
		}

		self::assertFalse( $plugin->siteState()->enable( $this->issuer ) );
		self::assertTrue( $plugin->siteState()->recordDiscoveryVerification( $this->issuer ) );
		self::assertTrue( $plugin->siteState()->enable( $this->issuer ) );
		self::assertTrue( $plugin->siteState()->isEnabled() );

		$enabled = $this->dispatch( 'GET', '/charter/v1/metadata/authorization-server' );
		self::assertSame( 200, $enabled->get_status() );
		self::assertSame( array( 'code' ), $enabled->get_data()['response_types_supported'] );
		self::assertSame( array( 'authorization_code', 'refresh_token' ), $enabled->get_data()['grant_types_supported'] );
		self::assertSame( array( 'S256' ), $enabled->get_data()['code_challenge_methods_supported'] );
		self::assertSame( array( 'none', 'client_secret_post' ), $enabled->get_data()['token_endpoint_auth_methods_supported'] );
		self::assertSame( ( new EndpointUrls( $this->issuer ) )->revocationEndpoint(), $enabled->get_data()['revocation_endpoint'] );
		self::assertSame( array( 'none', 'client_secret_post' ), $enabled->get_data()['revocation_endpoint_auth_methods_supported'] );

		$enabledResource = $this->dispatch( 'GET', '/charter/v1/metadata/protected-resource' );
		self::assertSame( array( $this->issuer ), $enabledResource->get_data()['authorization_servers'] );
	}

	/**
	 * Verifies an untrusted request host cannot redefine or operate the issuer.
	 *
	 * @since 0.1.0
	 */
	public function testRequestEnvironmentMustMatchCanonicalIssuer(): void {
		$this->enableIssuer();
		$server = $_SERVER;

		try {
			$_SERVER['HTTP_HOST']              = 'attacker.example.test';
			$_SERVER['HTTP_X_FORWARDED_HOST']  = (string) wp_parse_url( $this->issuer, PHP_URL_HOST );
			$_SERVER['HTTP_X_FORWARDED_PROTO'] = (string) wp_parse_url( $this->issuer, PHP_URL_SCHEME );

			$metadata = $this->dispatch( 'GET', '/charter/v1/metadata/authorization-server' );
			self::assertSame( 404, $metadata->get_status() );

			try {
				Plugin::boot()->authorization()->validate( $this->authorizationParameters() );
				self::fail( 'A mismatched direct request origin must not operate the issuer.' );
			} catch ( ProtocolException $exception ) {
				self::assertSame( 'temporarily_unavailable', $exception->error() );
			}

			$_SERVER                = $server;
			$_SERVER['HTTP_HOST']   = (string) wp_parse_url( $this->issuer, PHP_URL_HOST );
			$_SERVER['HTTPS']       = 'on';
			$_SERVER['SERVER_PORT'] = '443';
			$wrongSchemeMetadata    = $this->dispatch( 'GET', '/charter/v1/metadata/authorization-server' );
			self::assertSame( 404, $wrongSchemeMetadata->get_status() );
		} finally {
			$_SERVER = $server;
		}
	}

	/**
	 * Verifies a complete issuer-bound public-client flow and negative exchanges.
	 *
	 * @since 0.1.0
	 */
	public function testAuthorizationCodeFlowUsesS256AndSingleUseCredentials(): void {
		$this->enableIssuer();
		self::assertSame(
			'https://client.example.test/callback?existing=a%2Fb&code=exact%20code&iss=' . rawurlencode( $this->issuer ),
			AuthorizationService::redirectWithParameters(
				'https://client.example.test/callback?existing=a%2Fb',
				array(
					'code' => 'exact code',
					'iss'  => $this->issuer,
				)
			)
		);
		$code = $this->authorizeCode();

		$wrongVerifier = $this->exchangeCode(
			$code,
			array( 'code_verifier' => str_repeat( 'z', 43 ) )
		);
		self::assertSame( 400, $wrongVerifier->get_status() );
		self::assertSame( 'invalid_grant', $wrongVerifier->get_data()['error'] );

		$wrongResource = $this->exchangeCode(
			$code,
			array( 'resource' => $this->issuer . '/wrong' )
		);
		self::assertSame( 400, $wrongResource->get_status() );
		self::assertSame( 'invalid_target', $wrongResource->get_data()['error'] );

		$duplicateRequest = new WP_REST_Request( 'POST', '/charter/v1/token' );
		$duplicateRequest->set_header( 'Content-Type', 'application/x-www-form-urlencoded' );
		$duplicateRequest->set_body(
			'grant_type=authorization_code&client_id=charter-http-one&client_id=charter-http-two&code=' . rawurlencode( $code ) . '&code_verifier=' . rawurlencode( self::VERIFIER )
		);
		$duplicate = $this->server->dispatch( $duplicateRequest );
		self::assertSame( 400, $duplicate->get_status() );
		self::assertSame( 'invalid_request', $duplicate->get_data()['error'] );

		$tokenResponse = $this->exchangeCode( $code );
		self::assertSame( 200, $tokenResponse->get_status() );
		$tokenData = $tokenResponse->get_data();
		self::assertSame( 'Bearer', $tokenData['token_type'] );
		self::assertSame( 3600, $tokenData['expires_in'] );
		self::assertSame( AuthorizationService::GENERAL_SCOPE, $tokenData['scope'] );
		self::assertSame( $this->issuer, $tokenData['resource'] );
		self::assertIsString( $tokenData['access_token'] );

		$protectedRequest = new WP_REST_Request( 'GET', '/charter-test/v1/protected' );
		$protectedRequest->set_header( 'Authorization', 'Bearer ' . $tokenData['access_token'] );
		$protected = $this->server->dispatch( $protectedRequest );
		self::assertSame( 200, $protected->get_status() );
		self::assertSame( $this->userId, $protected->get_data()['user_id'] );
		self::assertSame( self::CLIENT_ID, $protected->get_data()['client_id'] );
		self::assertSame( $this->issuer, $protected->get_data()['resource'] );
		self::assertSame( 0, get_current_user_id(), 'Bearer identity must be removed after callbacks.' );

		// phpcs:ignore WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedHooknameFound -- Exercises the installed production Allow pass.
		$protected = apply_filters( 'rest_post_dispatch', $protected, $this->server, $protectedRequest );
		self::assertInstanceOf( \WP_REST_Response::class, $protected );
		self::assertSame( 'GET', $protected->get_headers()['Allow'] );
		self::assertSame( 0, get_current_user_id(), 'The Allow pass must also clean up Bearer identity.' );
		self::assertNull( Plugin::boot()->bearerAuthenticator()->currentContext() );

		$replay = $this->exchangeCode( $code );
		self::assertSame( 400, $replay->get_status() );
		self::assertSame( 'invalid_grant', $replay->get_data()['error'] );

		$revoked = $this->server->dispatch( $protectedRequest );
		self::assertSame( 401, $revoked->get_status(), 'Authorization-code replay must revoke issued descendants.' );

		global $wpdb;
		$rows    = $wpdb->get_results( 'SELECT * FROM ' . Schema::credentialTable(), ARRAY_A ); // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching,WordPress.DB.PreparedSQL.NotPrepared -- Test-only inspection of the fixed current-site table.
		$encoded = wp_json_encode( $rows );
		self::assertIsString( $encoded );
		self::assertStringNotContainsString( $code, $encoded );
		self::assertStringNotContainsString( $tokenData['access_token'], $encoded );
	}

	/**
	 * Verifies confidential authentication and rotating refresh replay closure.
	 *
	 * @since 0.1.0
	 */
	public function testConfidentialClientRotatesRefreshTokensAndReplayRevokesGrant(): void {
		$this->enableIssuer();
		$plugin = Plugin::boot();
		$secret = $plugin->clients()->registerConfidentialClient(
			$this->issuer,
			self::CONFIDENTIAL_CLIENT_ID,
			'Charter confidential integration client',
			array( self::CONFIDENTIAL_REDIRECT_URI ),
			true
		);
		self::assertStringStartsWith( 'chs_', $secret );
		$clientOption   = get_option( 'charter_oauth_clients' );
		$encodedClients = wp_json_encode( $clientOption );
		self::assertIsString( $encodedClients );
		self::assertStringNotContainsString( $secret, $encodedClients );

		$authorization = $plugin->authorization();
		$parameters    = array(
			'response_type'         => 'code',
			'client_id'             => self::CONFIDENTIAL_CLIENT_ID,
			'redirect_uri'          => self::CONFIDENTIAL_REDIRECT_URI,
			'code_challenge'        => TokenService::s256Challenge( self::VERIFIER ),
			'code_challenge_method' => 'S256',
			'resource'              => $this->issuer,
			'scope'                 => AuthorizationService::GENERAL_SCOPE . ' ' . AuthorizationService::OFFLINE_ACCESS_SCOPE,
			'state'                 => 'confidential-state',
		);
		$consent       = $authorization->begin( $parameters, $this->userId );
		self::assertTrue( $consent['request']->continuingAccessRequested() );
		$redirect = $authorization->complete( $consent['transaction'], $this->userId, true );
		$code     = self::queryParameter( $redirect, 'code' );

		$missingSecret = $this->dispatchToken(
			array(
				'grant_type'    => Client::GRANT_AUTHORIZATION_CODE,
				'client_id'     => self::CONFIDENTIAL_CLIENT_ID,
				'code'          => $code,
				'code_verifier' => self::VERIFIER,
			)
		);
		self::assertSame( 401, $missingSecret->get_status() );
		self::assertSame( 'invalid_client', $missingSecret->get_data()['error'] );

		$wrongSecret = $this->dispatchToken(
			array(
				'grant_type'    => Client::GRANT_AUTHORIZATION_CODE,
				'client_id'     => self::CONFIDENTIAL_CLIENT_ID,
				'client_secret' => 'not-the-client-secret',
				'code'          => $code,
				'code_verifier' => self::VERIFIER,
			)
		);
		self::assertSame( 401, $wrongSecret->get_status() );

		$basicRequest = new WP_REST_Request( 'POST', '/charter/v1/token' );
		$basicRequest->set_header( 'Content-Type', 'application/x-www-form-urlencoded' );
		$basicRequest->set_header( 'Authorization', 'Basic ignored' );
		$basicRequest->set_body_params(
			array(
				'grant_type'    => Client::GRANT_AUTHORIZATION_CODE,
				'client_id'     => self::CONFIDENTIAL_CLIENT_ID,
				'client_secret' => $secret,
				'code'          => $code,
				'code_verifier' => self::VERIFIER,
			)
		);
		$basic = $this->server->dispatch( $basicRequest );
		self::assertSame( 401, $basic->get_status() );
		self::assertSame( 'invalid_client', $basic->get_data()['error'] );

		$issued = $this->dispatchToken(
			array(
				'grant_type'    => Client::GRANT_AUTHORIZATION_CODE,
				'client_id'     => self::CONFIDENTIAL_CLIENT_ID,
				'client_secret' => $secret,
				'code'          => $code,
				'code_verifier' => self::VERIFIER,
				'resource'      => $this->issuer,
			)
		);
		self::assertSame( 200, $issued->get_status() );
		$issuedData = $issued->get_data();
		self::assertIsString( $issuedData['access_token'] ?? null );
		self::assertIsString( $issuedData['refresh_token'] ?? null );
		self::assertSame( AuthorizationService::GENERAL_SCOPE, $issuedData['scope'] );

		$wrongResource = $this->dispatchRefresh( $issuedData['refresh_token'], $secret, array( 'resource' => $this->issuer . '/wrong' ) );
		self::assertSame( 400, $wrongResource->get_status() );
		self::assertSame( 'invalid_target', $wrongResource->get_data()['error'] );

		$rotated = $this->dispatchRefresh( $issuedData['refresh_token'], $secret );
		self::assertSame( 200, $rotated->get_status() );
		$rotatedData = $rotated->get_data();
		self::assertIsString( $rotatedData['access_token'] ?? null );
		self::assertIsString( $rotatedData['refresh_token'] ?? null );
		self::assertNotSame( $issuedData['refresh_token'], $rotatedData['refresh_token'] );
		self::assertSame( $this->issuer, $rotatedData['resource'] );

		$protected = $this->dispatchBearer( '/charter-test/v1/protected', $rotatedData['access_token'] );
		self::assertSame( 200, $protected->get_status() );

		$replay = $this->dispatchRefresh( $issuedData['refresh_token'], $secret );
		self::assertSame( 400, $replay->get_status() );
		self::assertSame( 'invalid_grant', $replay->get_data()['error'] );
		self::assertSame( 401, $this->dispatchBearer( '/charter-test/v1/protected', $issuedData['access_token'] )->get_status() );
		self::assertSame( 401, $this->dispatchBearer( '/charter-test/v1/protected', $rotatedData['access_token'] )->get_status() );
		self::assertSame( 400, $this->dispatchRefresh( $rotatedData['refresh_token'], $secret )->get_status() );

		$persisted = ( new TransactionManager() )->run(
			static function ( \mysqli $database ): string {
				$table  = Schema::credentialTable();
				$result = $database->query( "SELECT credential_type,digest,issuer,resource,client_id,redirect_uri,user_id,scope,code_challenge,request_state,expires_at,consumed_at,created_at,grant_id,parent_id,continuing_access FROM `{$table}`" ); // phpcs:ignore WordPress.DB.RestrictedFunctions.mysql_mysqli,WordPress.DB.PreparedSQL.InterpolatedNotPrepared -- Test-only read of a fixed validated current-site table name.
				self::assertInstanceOf( \mysqli_result::class, $result );
				$rows = $result->fetch_all( MYSQLI_ASSOC );
				$result->free();
				$encoded = wp_json_encode( $rows );
				self::assertIsString( $encoded );

				return $encoded;
			}
		);
		foreach ( array( $code, $issuedData['access_token'], $issuedData['refresh_token'], $rotatedData['access_token'], $rotatedData['refresh_token'], $secret ) as $credential ) {
			self::assertStringNotContainsString( $credential, $persisted );
		}

		$secondConsent = $authorization->begin( $parameters, $this->userId );
		$secondCode    = self::queryParameter(
			$authorization->complete( $secondConsent['transaction'], $this->userId, true ),
			'code'
		);
		$secondIssued  = $this->dispatchToken(
			array(
				'grant_type'    => Client::GRANT_AUTHORIZATION_CODE,
				'client_id'     => self::CONFIDENTIAL_CLIENT_ID,
				'client_secret' => $secret,
				'code'          => $secondCode,
				'code_verifier' => self::VERIFIER,
			)
		);
		self::assertSame( 200, $secondIssued->get_status() );
		$secondData = $secondIssued->get_data();
		self::assertIsString( $secondData['access_token'] ?? null );
		self::assertIsString( $secondData['refresh_token'] ?? null );

		$missingRevocationSecret = $this->dispatchRevocation(
			array(
				'client_id' => self::CONFIDENTIAL_CLIENT_ID,
				'token'     => $secondData['refresh_token'],
			)
		);
		self::assertSame( 401, $missingRevocationSecret->get_status() );
		self::assertSame( 200, $this->dispatchBearer( '/charter-test/v1/protected', $secondData['access_token'] )->get_status() );

		$revoked = $this->dispatchRevocation(
			array(
				'client_id'       => self::CONFIDENTIAL_CLIENT_ID,
				'client_secret'   => $secret,
				'token'           => $secondData['refresh_token'],
				'token_type_hint' => CredentialStore::REFRESH_TOKEN,
			)
		);
		self::assertSame( 200, $revoked->get_status() );
		self::assertNull( $revoked->get_data() );
		self::assertSame( 401, $this->dispatchBearer( '/charter-test/v1/protected', $secondData['access_token'] )->get_status() );
		self::assertSame( 400, $this->dispatchRefresh( $secondData['refresh_token'], $secret )->get_status() );
	}

	/**
	 * Verifies public refresh rotation never depends on a client secret.
	 *
	 * @since 0.1.0
	 */
	public function testPublicClientRotatesRefreshTokensWithoutSecret(): void {
		$this->enableIssuer();
		$plugin = Plugin::boot();
		self::assertTrue(
			$plugin->clients()->registerPublicClient(
				$this->issuer,
				self::PUBLIC_REFRESH_CLIENT_ID,
				'Charter public refresh client',
				array( self::PUBLIC_REFRESH_REDIRECT_URI ),
				true
			)
		);

		$consent = $plugin->authorization()->begin(
			array(
				'response_type'         => 'code',
				'client_id'             => self::PUBLIC_REFRESH_CLIENT_ID,
				'redirect_uri'          => 'http://127.0.0.1:53127/callback',
				'code_challenge'        => TokenService::s256Challenge( self::VERIFIER ),
				'code_challenge_method' => 'S256',
				'resource'              => $this->issuer,
				'scope'                 => AuthorizationService::GENERAL_SCOPE,
			),
			$this->userId
		);
		self::assertTrue( $consent['request']->continuingAccessRequested(), 'A registered refresh grant is a continuing-access signal.' );
		$code = self::queryParameter(
			$plugin->authorization()->complete( $consent['transaction'], $this->userId, true ),
			'code'
		);

		$secretRejected = $this->dispatchToken(
			array(
				'grant_type'    => Client::GRANT_AUTHORIZATION_CODE,
				'client_id'     => self::PUBLIC_REFRESH_CLIENT_ID,
				'client_secret' => 'public-clients-have-no-secret',
				'code'          => $code,
				'code_verifier' => self::VERIFIER,
			)
		);
		self::assertSame( 401, $secretRejected->get_status() );
		self::assertSame( 'invalid_client', $secretRejected->get_data()['error'] );

		$issued = $this->dispatchToken(
			array(
				'grant_type'    => Client::GRANT_AUTHORIZATION_CODE,
				'client_id'     => self::PUBLIC_REFRESH_CLIENT_ID,
				'code'          => $code,
				'code_verifier' => self::VERIFIER,
			)
		);
		self::assertSame( 200, $issued->get_status() );
		$issuedData = $issued->get_data();
		self::assertIsString( $issuedData['refresh_token'] ?? null );

		$rotated = $this->dispatchToken(
			array(
				'grant_type'    => Client::GRANT_REFRESH_TOKEN,
				'client_id'     => self::PUBLIC_REFRESH_CLIENT_ID,
				'refresh_token' => $issuedData['refresh_token'],
			)
		);
		self::assertSame( 200, $rotated->get_status() );
		$rotatedData = $rotated->get_data();
		self::assertIsString( $rotatedData['refresh_token'] ?? null );
		self::assertNotSame( $issuedData['refresh_token'], $rotatedData['refresh_token'] );

		$replay = $this->dispatchToken(
			array(
				'grant_type'    => Client::GRANT_REFRESH_TOKEN,
				'client_id'     => self::PUBLIC_REFRESH_CLIENT_ID,
				'refresh_token' => $issuedData['refresh_token'],
			)
		);
		self::assertSame( 400, $replay->get_status() );
		self::assertSame( 'invalid_grant', $replay->get_data()['error'] );
		self::assertSame( 401, $this->dispatchBearer( '/charter-test/v1/protected', $rotatedData['access_token'] )->get_status() );
	}

	/**
	 * Verifies consent is reused only for an exact active authorization.
	 *
	 * @since 0.1.0
	 */
	public function testConsentReuseRequiresExactActiveGrantAndStepUpPrompts(): void {
		$this->enableIssuer();
		$authorization = Plugin::boot()->authorization();
		$parameters    = $this->authorizationParameters();

		$first = $authorization->begin( $parameters, $this->userId );
		self::assertNull( $first['reusable_grant_id'] );
		$firstCode   = self::queryParameter(
			$authorization->complete( $first['transaction'], $this->userId, true ),
			'code'
		);
		$firstIssued = $this->exchangeCode( $firstCode );
		self::assertSame( 200, $firstIssued->get_status() );
		$firstData = $firstIssued->get_data();
		self::assertIsString( $firstData['access_token'] ?? null );

		$parameters['state'] = 'changed-non-material-state';
		$second              = $authorization->begin( $parameters, $this->userId );
		self::assertIsInt( $second['reusable_grant_id'] );
		$reusedGrantId = $second['reusable_grant_id'];
		$secondCode    = self::queryParameter(
			$authorization->complete( $second['transaction'], $this->userId, true, $reusedGrantId ),
			'code'
		);
		$secondIssued  = $this->exchangeCode( $secondCode );
		self::assertSame( 200, $secondIssued->get_status() );
		$secondData = $secondIssued->get_data();
		self::assertIsString( $secondData['access_token'] ?? null );
		self::assertNotNull( Plugin::boot()->credentials()->findGrant( $reusedGrantId ) );

		$stepUpParameters          = $parameters;
		$stepUpParameters['scope'] = AuthorizationService::GENERAL_SCOPE . ' ' . AuthorizationService::OFFLINE_ACCESS_SCOPE;
		$stepUp                    = $authorization->begin( $stepUpParameters, $this->userId );
		self::assertNull( $stepUp['reusable_grant_id'], 'New continuing access requires fresh consent.' );
		$denied = $authorization->complete( $stepUp['transaction'], $this->userId, false );
		self::assertSame( 'access_denied', self::queryParameter( $denied, 'error' ) );

		$revoked = $this->dispatchRevocation(
			array(
				'client_id' => self::CLIENT_ID,
				'token'     => $firstData['access_token'],
			)
		);
		self::assertSame( 200, $revoked->get_status() );
		self::assertSame( 401, $this->dispatchBearer( '/charter-test/v1/protected', $secondData['access_token'] )->get_status() );

		$afterRevocation = $authorization->begin( $parameters, $this->userId );
		self::assertNull( $afterRevocation['reusable_grant_id'], 'Revoked consent cannot suppress a prompt.' );
	}

	/**
	 * Verifies personal authorization inventory is isolated by issuer and user.
	 *
	 * @since 0.1.0
	 */
	public function testPersonalGrantInventoryCannotCrossUserOrIssuerBoundaries(): void {
		$this->enableIssuer();
		$plugin          = Plugin::boot();
		$firstToken      = $this->issueAccessToken();
		$otherUserId     = self::factory()->user->create( array( 'role' => 'subscriber' ) );
		$authorization   = $plugin->authorization();
		$otherConsent    = $authorization->begin( $this->authorizationParameters(), $otherUserId );
		$otherCode       = self::queryParameter(
			$authorization->complete( $otherConsent['transaction'], $otherUserId, true ),
			'code'
		);
		$otherTokenReply = $this->exchangeCode( $otherCode );
		self::assertSame( 200, $otherTokenReply->get_status() );
		$otherTokenData = $otherTokenReply->get_data();
		self::assertIsString( $otherTokenData['access_token'] ?? null );

		$firstUserGrants = $plugin->credentials()->listActiveGrantsForUser( $this->issuer, $this->userId );
		$otherUserGrants = $plugin->credentials()->listActiveGrantsForUser( $this->issuer, $otherUserId );
		self::assertCount( 1, $firstUserGrants );
		self::assertCount( 1, $otherUserGrants );
		self::assertSame( $this->userId, $firstUserGrants[0]->userId() );
		self::assertSame( $otherUserId, $otherUserGrants[0]->userId() );
		self::assertNotSame( $firstUserGrants[0]->id(), $otherUserGrants[0]->id() );
		self::assertSame( array(), $plugin->credentials()->listActiveGrantsForUser( $this->issuer . '/other', $this->userId ) );

		self::assertTrue( $plugin->credentials()->revokeGrant( $firstUserGrants[0]->id(), time(), 'user_revocation' ) );
		self::assertSame( array(), $plugin->credentials()->listActiveGrantsForUser( $this->issuer, $this->userId ) );
		self::assertCount( 1, $plugin->credentials()->listActiveGrantsForUser( $this->issuer, $otherUserId ) );
		self::assertSame( 401, $this->dispatchBearer( '/charter-test/v1/protected', $firstToken )->get_status() );
		self::assertSame( 200, $this->dispatchBearer( '/charter-test/v1/protected', $otherTokenData['access_token'] )->get_status() );
	}

	/**
	 * Verifies deterministic WordPress identity events revoke only that user.
	 *
	 * @since 0.1.0
	 */
	public function testPasswordAndUserDeletionEventsCloseAffectedUserGrants(): void {
		$this->enableIssuer();
		$firstToken  = $this->issueAccessToken();
		$otherUserId = self::factory()->user->create( array( 'role' => 'subscriber' ) );
		$otherToken  = $this->issueAccessTokenForUser( $otherUserId );

		do_action( 'wp_set_password', 'not-a-real-password-secret', $this->userId ); // phpcs:ignore WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedHooknameFound -- Exercises the exact Core password lifecycle action without changing the test user's login credential.
		self::assertSame( 401, $this->dispatchBearer( '/charter-test/v1/protected', $firstToken )->get_status() );
		self::assertSame( 200, $this->dispatchBearer( '/charter-test/v1/protected', $otherToken )->get_status() );

		$replacementToken = $this->issueAccessToken();
		do_action( 'delete_user', $this->userId ); // phpcs:ignore WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedHooknameFound -- Exercises the exact Core single-site deletion lifecycle action without deleting the PHPUnit fixture user.
		self::assertSame( 401, $this->dispatchBearer( '/charter-test/v1/protected', $replacementToken )->get_status() );
		self::assertSame( 200, $this->dispatchBearer( '/charter-test/v1/protected', $otherToken )->get_status() );

		$persisted = ( new TransactionManager() )->run(
			static function ( \mysqli $database ): string {
				$credentials = Schema::credentialTable();
				$grants      = Schema::grantTable();
				$rows        = array();
				foreach ( array( $credentials, $grants ) as $table ) {
					$result = $database->query( "SELECT * FROM `{$table}`" ); // phpcs:ignore WordPress.DB.RestrictedFunctions.mysql_mysqli,WordPress.DB.PreparedSQL.InterpolatedNotPrepared -- Test-only read of fixed validated current-site tables.
					self::assertInstanceOf( \mysqli_result::class, $result );
					$rows[] = $result->fetch_all( MYSQLI_ASSOC );
					$result->free();
				}
				$encoded = wp_json_encode( $rows );
				self::assertIsString( $encoded );

				return $encoded;
			}
		);
		self::assertStringNotContainsString( 'not-a-real-password-secret', $persisted );
	}

	/**
	 * Verifies RFC 7009 is non-revealing and enforces exact client ownership.
	 *
	 * @since 0.1.0
	 */
	public function testRevocationClosesOwnedGrantWithoutBecomingATokenOracle(): void {
		$this->enableIssuer();
		$accessToken = $this->issueAccessToken();
		self::assertTrue(
			Plugin::boot()->clients()->registerPublicClient(
				$this->issuer,
				'charter-other-public-client',
				'Other public client',
				array( 'https://other.example.test/callback' )
			)
		);

		$unknown = $this->dispatchRevocation(
			array(
				'client_id'       => self::CLIENT_ID,
				'token'           => 'cha_' . str_repeat( 'z', 43 ),
				'token_type_hint' => 'unsupported-hint',
			)
		);
		self::assertSame( 200, $unknown->get_status() );
		self::assertNull( $unknown->get_data() );

		$crossClient = $this->dispatchRevocation(
			array(
				'client_id' => 'charter-other-public-client',
				'token'     => $accessToken,
			)
		);
		self::assertSame( 200, $crossClient->get_status() );
		self::assertSame( 200, $this->dispatchBearer( '/charter-test/v1/protected', $accessToken )->get_status() );

		$basicRequest = new WP_REST_Request( 'POST', '/charter/v1/revoke' );
		$basicRequest->set_header( 'Content-Type', 'application/x-www-form-urlencoded' );
		$basicRequest->set_header( 'Authorization', 'Basic ignored' );
		$basicRequest->set_body_params(
			array(
				'client_id' => self::CLIENT_ID,
				'token'     => $accessToken,
			)
		);
		$basic = $this->server->dispatch( $basicRequest );
		self::assertSame( 401, $basic->get_status() );
		self::assertSame( 'invalid_client', $basic->get_data()['error'] );

		$duplicateRequest = new WP_REST_Request( 'POST', '/charter/v1/revoke' );
		$duplicateRequest->set_header( 'Content-Type', 'application/x-www-form-urlencoded' );
		$duplicateRequest->set_body( 'client_id=' . self::CLIENT_ID . '&token=first&token=second' );
		$duplicate = $this->server->dispatch( $duplicateRequest );
		self::assertSame( 400, $duplicate->get_status() );
		self::assertSame( 'invalid_request', $duplicate->get_data()['error'] );

		$revoked = $this->dispatchRevocation(
			array(
				'client_id'       => self::CLIENT_ID,
				'token'           => $accessToken,
				'token_type_hint' => CredentialStore::ACCESS_TOKEN,
			)
		);
		self::assertSame( 200, $revoked->get_status() );
		self::assertNull( $revoked->get_data() );
		self::assertSame( 'no-store', $revoked->get_headers()['Cache-Control'] );
		self::assertSame( 401, $this->dispatchBearer( '/charter-test/v1/protected', $accessToken )->get_status() );
	}

	/**
	 * Verifies reversible pause and lockdown without implicit OAuth data loss.
	 */
	public function testEmergencyContainmentPreservesStateAndProtocolOwnershipUntilExplicitRevocation(): void {
		$this->enableIssuer();
		$plugin          = Plugin::boot();
		$administrator   = self::factory()->user->create( array( 'role' => 'administrator' ) );
		$refreshClient   = 'charter-containment-refresh-client';
		$refreshRedirect = 'https://containment.example.test/callback';
		self::assertTrue( $plugin->clients()->registerPublicClient( $this->issuer, $refreshClient, 'Containment refresh client', array( $refreshRedirect ), true ) );

		$refreshParameters = array(
			'response_type'         => 'code',
			'client_id'             => $refreshClient,
			'redirect_uri'          => $refreshRedirect,
			'code_challenge'        => TokenService::s256Challenge( self::VERIFIER ),
			'code_challenge_method' => 'S256',
			'resource'              => $this->issuer,
			'scope'                 => AuthorizationService::GENERAL_SCOPE . ' ' . AuthorizationService::OFFLINE_ACCESS_SCOPE,
			'state'                 => 'containment-refresh-state',
		);
		$refreshConsent    = $plugin->authorization()->begin( $refreshParameters, $this->userId );
		$refreshCode       = self::queryParameter( $plugin->authorization()->complete( $refreshConsent['transaction'], $this->userId, true ), 'code' );
		$refreshIssued     = $this->dispatchToken(
			array(
				'grant_type'    => Client::GRANT_AUTHORIZATION_CODE,
				'client_id'     => $refreshClient,
				'code'          => $refreshCode,
				'code_verifier' => self::VERIFIER,
				'redirect_uri'  => $refreshRedirect,
				'resource'      => $this->issuer,
			)
		);
		self::assertSame( 200, $refreshIssued->get_status() );
		$refreshData = $refreshIssued->get_data();
		self::assertIsString( $refreshData['access_token'] ?? null );
		self::assertIsString( $refreshData['refresh_token'] ?? null );

		$revocableAccess = $this->issueAccessToken();
		$pendingCode     = $this->authorizeCode();
		$pendingConsent  = $plugin->authorization()->begin( $this->authorizationParameters(), $this->userId );
		$before          = $this->oauthStateCounts();
		$containmentAt   = time() - 10;
		self::assertSame( 'good', $plugin->containment()->siteHealthResult()['status'] );

		self::assertTrue(
			$plugin->containment()->transition(
				EmergencyContainment::ISSUANCE_PAUSED,
				EmergencyContainment::ACTOR_SITE_ADMIN,
				$administrator,
				$containmentAt,
				$this->issuer
			)
		);
		self::assertSame( EmergencyContainment::ISSUANCE_PAUSED, $plugin->containment()->mode() );
		self::assertSame( 'recommended', $plugin->containment()->siteHealthResult()['status'] );
		$metadata = $this->dispatch( 'GET', '/charter/v1/metadata/authorization-server' );
		self::assertSame( 200, $metadata->get_status() );
		self::assertArrayNotHasKey( 'registration_endpoint', $metadata->get_data() );

		$dcrRequest = new WP_REST_Request( 'POST', '/charter/v1/register' );
		$dcrRequest->set_header( 'Content-Type', 'application/json' );
		$dcrRequest->set_body(
			(string) wp_json_encode(
				array(
					'client_name'                => 'Paused registration',
					'redirect_uris'              => array( 'https://paused.example.test/callback' ),
					'token_endpoint_auth_method' => 'none',
					'grant_types'                => array( Client::GRANT_AUTHORIZATION_CODE ),
					'response_types'             => array( 'code' ),
				)
			)
		);
		$dcrPaused = $this->server->dispatch( $dcrRequest );
		self::assertSame( 503, $dcrPaused->get_status() );
		self::assertSame( 'temporarily_unavailable', $dcrPaused->get_data()['error'] );

		try {
			$plugin->authorization()->begin( $this->authorizationParameters(), $this->userId );
			self::fail( 'Pause must reject a new authorization before it creates a transaction.' );
		} catch ( ProtocolException $exception ) {
			self::assertSame( 'temporarily_unavailable', $exception->error() );
			self::assertNull( $exception->redirectUri(), 'An unvalidated authorization request must not gain redirect authority.' );
		}
		try {
			$plugin->authorization()->complete( $pendingConsent['transaction'], $this->userId, true );
			self::fail( 'Pause must not issue a code from an existing consent transaction.' );
		} catch ( ProtocolException $exception ) {
			self::assertSame( 'temporarily_unavailable', $exception->error() );
			self::assertSame( self::REDIRECT_URI, $exception->redirectUri(), 'Only the stored validated authorization request owns the client redirect.' );
			self::assertSame( 'client-state', $exception->state() );
		}

		$codePaused = $this->exchangeCode( $pendingCode );
		self::assertSame( 503, $codePaused->get_status() );
		self::assertSame( 'temporarily_unavailable', $codePaused->get_data()['error'] );
		$refreshPaused = $this->dispatchToken(
			array(
				'grant_type'    => Client::GRANT_REFRESH_TOKEN,
				'client_id'     => $refreshClient,
				'refresh_token' => $refreshData['refresh_token'],
			)
		);
		self::assertSame( 503, $refreshPaused->get_status() );
		self::assertSame( 'temporarily_unavailable', $refreshPaused->get_data()['error'] );
		self::assertSame( 200, $this->dispatchBearer( '/charter-test/v1/protected', $refreshData['access_token'] )->get_status() );
		self::assertSame( 200, $this->dispatchBearer( '/charter-test/v1/public', $refreshData['access_token'] )->get_status() );
		self::assertSame( $before, $this->oauthStateCounts(), 'Pause must not mutate clients, grants, consents, or credentials.' );

		self::assertTrue(
			$plugin->containment()->transition(
				EmergencyContainment::LOCKDOWN,
				EmergencyContainment::ACTOR_SITE_ADMIN,
				$administrator,
				$containmentAt + 1,
				$this->issuer
			)
		);
		self::assertSame( 'critical', $plugin->containment()->siteHealthResult()['status'] );
		$lockedBearer = $this->dispatchBearer( '/charter-test/v1/protected', $refreshData['access_token'] );
		self::assertSame( 401, $lockedBearer->get_status() );
		self::assertSame( 'invalid_token', $lockedBearer->get_data()['error'] );
		self::assertSame( 200, $this->dispatchBearer( '/charter-test/v1/public', $refreshData['access_token'] )->get_status() );
		self::assertSame( $before, $this->oauthStateCounts(), 'Lockdown must not mutate clients, grants, consents, or credentials.' );
		$cleanupDuringLockdown = $plugin->cleanup()->execute( time() );
		self::assertIsArray( $cleanupDuringLockdown->deleted(), 'Issuer-local cleanup remains available during lockdown.' );
		self::assertSame( EmergencyContainment::LOCKDOWN, $plugin->containment()->mode(), 'Cleanup cannot change the explicit containment mode.' );

		wp_set_current_user( $this->userId );
		self::assertSame( 200, $this->dispatch( 'GET', '/charter-test/v1/protected' )->get_status(), 'Cookie authentication remains available during lockdown.' );
		$applicationPassword = WP_Application_Passwords::create_new_application_password( $this->userId, array( 'name' => 'Containment boundary' ) );
		self::assertIsArray( $applicationPassword );
		$user = get_userdata( $this->userId );
		self::assertNotFalse( $user );
		add_filter( 'wp_is_application_passwords_available', '__return_true' );
		add_filter( 'application_password_is_api_request', '__return_true' );
		try {
			wp_set_current_user( 0 );
			$_SERVER['PHP_AUTH_USER'] = $user->user_login;
			$_SERVER['PHP_AUTH_PW']   = $applicationPassword[0];
			$applicationUserId        = wp_validate_application_password( false );
			self::assertSame( $this->userId, $applicationUserId );
			wp_set_current_user( $applicationUserId );
			self::assertSame( 200, $this->dispatch( 'GET', '/charter-test/v1/protected' )->get_status(), 'Application Password authentication remains available during lockdown.' );
		} finally {
			remove_filter( 'wp_is_application_passwords_available', '__return_true' );
			remove_filter( 'application_password_is_api_request', '__return_true' );
			unset( $_SERVER['PHP_AUTH_USER'], $_SERVER['PHP_AUTH_PW'] );
			$GLOBALS['wp_rest_application_password_status'] = null; // phpcs:ignore WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedVariableFound -- Resets Core authentication test state.
			WP_Application_Passwords::delete_all_application_passwords( $this->userId );
			wp_set_current_user( 0 );
		}

		$revokedDuringLockdown = $this->dispatchRevocation(
			array(
				'client_id' => self::CLIENT_ID,
				'token'     => $revocableAccess,
			)
		);
		self::assertSame( 200, $revokedDuringLockdown->get_status(), 'RFC 7009 remains available during lockdown.' );

		self::assertTrue(
			$plugin->containment()->transition(
				EmergencyContainment::RESUMED,
				EmergencyContainment::ACTOR_SITE_ADMIN,
				$administrator,
				$containmentAt + 2,
				$this->issuer
			)
		);
		self::assertSame( 'good', $plugin->containment()->siteHealthResult()['status'] );
		$resumedMetadata = $this->dispatch( 'GET', '/charter/v1/metadata/authorization-server' );
		self::assertArrayHasKey( 'registration_endpoint', $resumedMetadata->get_data() );
		self::assertSame( 200, $this->exchangeCode( $pendingCode )->get_status(), 'The unconsumed code remains exchangeable after resume.' );
		$resumedConsent = $plugin->authorization()->complete( $pendingConsent['transaction'], $this->userId, true );
		self::assertNotSame( '', self::queryParameter( $resumedConsent, 'code' ), 'The unconsumed consent transaction remains usable after resume.' );
		$resumedRefresh = $this->dispatchToken(
			array(
				'grant_type'    => Client::GRANT_REFRESH_TOKEN,
				'client_id'     => $refreshClient,
				'refresh_token' => $refreshData['refresh_token'],
			)
		);
		self::assertSame( 200, $resumedRefresh->get_status(), 'The unconsumed refresh token remains usable after resume.' );
		self::assertSame( 201, $this->server->dispatch( $dcrRequest )->get_status(), 'DCR resumes without changing its independent operator policy.' );

		$events = $plugin->audit()->listForIssuer( $this->issuer, 20 );
		$modes  = array_values( array_filter( $events, static fn ( $event ): bool => 'emergency_mode_changed' === $event->eventType() ) );
		self::assertCount( 3, $modes );
		self::assertSame( 'site_administrator_resumed', $modes[0]->reason() );
		self::assertSame( 'site_administrator_lockdown', $modes[1]->reason() );
		self::assertSame( 'site_administrator_issuance_paused', $modes[2]->reason() );
		$auditJson = wp_json_encode( $events );
		self::assertIsString( $auditJson );
		self::assertStringNotContainsString( $refreshData['access_token'], $auditJson );
		self::assertStringNotContainsString( $refreshData['refresh_token'], $auditJson );

		$permanentlyRevoked = $plugin->grantGovernance()->revokeAll( $this->issuer, $administrator, $containmentAt + 3 );
		self::assertNotSame( array(), $permanentlyRevoked, 'Permanent revoke-all remains a distinct explicit action.' );
		self::assertSame( 0, $plugin->credentials()->countActiveGrantsForIssuer( $this->issuer ) );
		self::assertSame( EmergencyContainment::RESUMED, $plugin->containment()->mode(), 'Permanent revocation does not silently change the reversible containment mode.' );
	}

	/** Verifies an applied mode retains truthful pending status until audit recovers. */
	public function testEmergencyContainmentReconcilesAnInterruptedAuditExactlyOnce(): void {
		$this->enableIssuer();
		$plugin      = Plugin::boot();
		$audit       = new class() implements AuditWriter {
			/**
			 * Whether the next audit write should fail.
			 *
			 * @var bool
			 */
			public bool $fail = true;

			/**
			 * Recorded exact test events.
			 *
			 * @var array<int, array{issuer:string,timestamp:int,event_type:string,outcome:string,reason:string,actor_user_id:?int}>
			 */
			public array $events = array();

			/**
			 * Records one exact event unless failure is enabled.
			 *
			 * @param string      $issuer Exact issuer.
			 * @param string      $eventType Stable event type.
			 * @param string      $outcome Stable outcome.
			 * @param string      $reason Stable reason.
			 * @param int|null    $actorUserId Acting WordPress user.
			 * @param int|null    $representedUserId Represented user.
			 * @param string|null $clientId Exact client identifier.
			 * @param string|null $sourceAddress Normalized source when relevant.
			 * @param int|null    $timestamp Event timestamp.
			 * @param string|null $resourceIdentifier Exact resource when applicable.
			 * @param string|null $scopes Canonical scope set when applicable.
			 * @throws \RuntimeException While failure is enabled.
			 */
			public function record( string $issuer, string $eventType, string $outcome, string $reason, ?int $actorUserId = null, ?int $representedUserId = null, ?string $clientId = null, ?string $sourceAddress = null, ?int $timestamp = null, ?string $resourceIdentifier = null, ?string $scopes = null ): void {
				unset( $representedUserId, $clientId, $sourceAddress, $resourceIdentifier, $scopes );
				if ( $this->fail || null === $timestamp ) {
					throw new \RuntimeException( 'charter_test_audit_interrupted' );
				}
				$this->events[] = array(
					'issuer'        => $issuer,
					'timestamp'     => $timestamp,
					'event_type'    => $eventType,
					'outcome'       => $outcome,
					'reason'        => $reason,
					'actor_user_id' => $actorUserId,
				);
			}

			/**
			 * Reports whether one exact event was already recorded.
			 *
			 * @param string   $issuer Exact issuer.
			 * @param int      $timestamp Exact event timestamp.
			 * @param string   $eventType Stable event type.
			 * @param string   $outcome Stable outcome.
			 * @param string   $reason Stable reason.
			 * @param int|null $actorUserId Acting WordPress user.
			 */
			public function hasEvent( string $issuer, int $timestamp, string $eventType, string $outcome, string $reason, ?int $actorUserId ): bool {
				foreach ( $this->events as $event ) {
					if ( array( $issuer, $timestamp, $eventType, $outcome, $reason, $actorUserId ) === array( $event['issuer'], $event['timestamp'], $event['event_type'], $event['outcome'], $event['reason'], $event['actor_user_id'] ) ) {
						return true;
					}
				}

				return false;
			}
		};
		$containment = new EmergencyContainment( $plugin->siteState(), $audit );
		$actorId     = self::factory()->user->create( array( 'role' => 'administrator' ) );
		$timestamp   = time();
		$before      = $this->oauthStateCounts();

		self::assertTrue( $containment->transition( EmergencyContainment::ISSUANCE_PAUSED, EmergencyContainment::ACTOR_SITE_ADMIN, $actorId, $timestamp, $this->issuer ) );
		self::assertSame( EmergencyContainment::ISSUANCE_PAUSED, $containment->mode(), 'Containment remains immediately effective when audit is interrupted.' );
		self::assertTrue( $containment->snapshot()['audit_pending'] );
		self::assertSame( 'critical', $containment->siteHealthResult()['status'] );
		self::assertSame( $before, $this->oauthStateCounts() );
		self::assertSame( array(), $audit->events );

		$audit->fail = false;
		self::assertTrue( $containment->transition( EmergencyContainment::ISSUANCE_PAUSED, EmergencyContainment::ACTOR_SITE_ADMIN, $actorId, $timestamp + 1, $this->issuer ) );
		self::assertFalse( $containment->snapshot()['audit_pending'] );
		self::assertSame( 'recommended', $containment->siteHealthResult()['status'] );
		self::assertCount( 1, $audit->events );
		self::assertSame( $timestamp, $audit->events[0]['timestamp'], 'Audit retry retains the original applied transition time.' );
		self::assertSame( 'site_administrator_issuance_paused', $audit->events[0]['reason'] );
		self::assertSame( $actorId, $audit->events[0]['actor_user_id'] );
		self::assertTrue( $containment->transition( EmergencyContainment::ISSUANCE_PAUSED, EmergencyContainment::ACTOR_SITE_ADMIN, $actorId, $timestamp + 2, $this->issuer ) );
		self::assertCount( 1, $audit->events, 'An already reconciled idempotent transition does not duplicate audit.' );

		self::assertTrue( $containment->transition( EmergencyContainment::RESUMED, EmergencyContainment::ACTOR_SITE_ADMIN, $actorId, $timestamp, $this->issuer ) );
		self::assertTrue( $containment->transition( EmergencyContainment::ISSUANCE_PAUSED, EmergencyContainment::ACTOR_SITE_ADMIN, $actorId, $timestamp, $this->issuer ) );
		self::assertCount( 3, $audit->events, 'Rapid same-actor transitions each retain a distinct audit identity.' );
		self::assertSame( array( $timestamp, $timestamp + 1, $timestamp + 2 ), array_column( $audit->events, 'timestamp' ) );
		self::assertSame( array( 'site_administrator_issuance_paused', 'site_administrator_resumed', 'site_administrator_issuance_paused' ), array_column( $audit->events, 'reason' ) );
	}

	/**
	 * Verifies public routes and existing WordPress authentication remain intact.
	 *
	 * @since 0.1.0
	 */
	public function testPublicAndWordPressAuthenticatedRoutesRemainIndependent(): void {
		$this->enableIssuer();

		$public = $this->dispatchBearer( '/charter-test/v1/public', 'not-a-valid-token' );
		self::assertSame( 200, $public->get_status() );
		self::assertSame( array( 'public' => true ), $public->get_data() );

		wp_set_current_user( $this->userId );
		$legacy = $this->dispatch( 'GET', '/charter-test/v1/protected' );
		self::assertSame( 200, $legacy->get_status() );
		self::assertSame( $this->userId, $legacy->get_data()['user_id'] );

		$mixedRequest = new WP_REST_Request( 'GET', '/charter-test/v1/protected' );
		$mixedRequest->set_header( 'Authorization', 'Bearer ' . str_repeat( 'a', 30 ) );
		$mixed = $this->server->dispatch( $mixedRequest );
		self::assertSame( 400, $mixed->get_status() );
		self::assertSame( 'invalid_request', $mixed->get_data()['error'] );
		self::assertStringNotContainsString( 'resource_metadata', $mixed->get_headers()['WWW-Authenticate'] );
		self::assertSame( $this->userId, get_current_user_id() );

		$applicationPassword = WP_Application_Passwords::create_new_application_password(
			$this->userId,
			array( 'name' => 'Charter production integration' )
		);
		self::assertIsArray( $applicationPassword );
		$user = get_userdata( $this->userId );
		self::assertNotFalse( $user );

		add_filter( 'wp_is_application_passwords_available', '__return_true' );
		add_filter( 'application_password_is_api_request', '__return_true' );
		try {
			$_SERVER['PHP_AUTH_USER'] = $user->user_login;
			$_SERVER['PHP_AUTH_PW']   = $applicationPassword[0];
			$validatedUserId          = wp_validate_application_password( false );
			self::assertSame( $this->userId, $validatedUserId );
			wp_set_current_user( $validatedUserId );
			self::assertTrue( $this->server->check_authentication() );

			$applicationAuthenticated = $this->dispatch( 'GET', '/charter-test/v1/protected' );
			self::assertSame( 200, $applicationAuthenticated->get_status() );
			self::assertSame( $this->userId, $applicationAuthenticated->get_data()['user_id'] );
		} finally {
			remove_filter( 'wp_is_application_passwords_available', '__return_true' );
			remove_filter( 'application_password_is_api_request', '__return_true' );
			unset( $_SERVER['PHP_AUTH_USER'], $_SERVER['PHP_AUTH_PW'] );
			$GLOBALS['wp_rest_application_password_status'] = null; // phpcs:ignore WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedVariableFound -- Resets Core authentication test state.
			WP_Application_Passwords::delete_all_application_passwords( $this->userId );
		}
	}

	/**
	 * Verifies Bearer challenges, resource/scope checks, and WordPress permissions.
	 *
	 * @since 0.1.0
	 */
	public function testProtectedRouteKeepsOAuthAndWordPressAuthorizationSeparate(): void {
		$this->enableIssuer();
		$token           = $this->issueAccessToken();
		$lowercaseScheme = new WP_REST_Request( 'GET', '/charter-test/v1/protected' );
		$lowercaseScheme->set_header( 'Authorization', 'bearer ' . $token );
		self::assertSame( 200, $this->server->dispatch( $lowercaseScheme )->get_status() );

		$missing = $this->dispatch( 'GET', '/charter-test/v1/protected' );
		self::assertSame( 401, $missing->get_status() );
		self::assertSame( 'Bearer scope="wordpress:access"', $missing->get_headers()['WWW-Authenticate'] ); // phpcs:ignore WordPress.WP.CapitalPDangit.MisspelledInText -- OAuth scope identifiers are case-sensitive protocol values.

		$invalid = $this->dispatchBearer( '/charter-test/v1/protected', 'cha_' . str_repeat( 'a', 43 ) );
		self::assertSame( 401, $invalid->get_status() );
		self::assertSame( 'Bearer error="invalid_token"', $invalid->get_headers()['WWW-Authenticate'] );

		$scope = $this->dispatchBearer( '/charter-test/v1/mcp', $token );
		self::assertSame( 401, $scope->get_status() );
		self::assertSame(
			'Bearer error="invalid_token", resource_metadata="' . ( new EndpointUrls( $this->issuer ) )->protectedResourceMetadata( $this->mcpResource() ) . '"',
			$scope->get_headers()['WWW-Authenticate']
		);

		$resource = $this->dispatchBearer( '/charter-test/v1/other-resource', $token );
		self::assertSame( 401, $resource->get_status() );
		self::assertSame( 'invalid_token', $resource->get_data()['error'] );

		$forbidden = $this->dispatchBearer( '/charter-test/v1/admin-only', $token );
		self::assertSame( 403, $forbidden->get_status() );
		self::assertSame( 'rest_forbidden', $forbidden->get_data()['code'] );
		self::assertArrayNotHasKey( 'WWW-Authenticate', $forbidden->get_headers() );
		self::assertSame( 0, get_current_user_id() );

		$nested = $this->dispatchBearer( '/charter-test/v1/nested', $token );
		self::assertSame( 200, $nested->get_status() );
		self::assertSame( 401, $nested->get_data()['inner_status'] );
		self::assertSame( $this->userId, $nested->get_data()['outer_user_id'] );
		self::assertSame( self::CLIENT_ID, $nested->get_data()['outer_client_id'] );
		self::assertSame( 0, get_current_user_id() );

		$multiRequest = new WP_REST_Request( 'GET', '/charter-test/v1/multi' );
		$multiRequest->set_header( 'Authorization', 'Bearer ' . $token );
		$multiHandlers = $this->server->get_routes()['/charter-test/v1/multi'] ?? null;
		self::assertIsArray( $multiHandlers );
		self::assertCount( 2, $multiHandlers );
		self::assertNotNull( ProtectedRoute::assignmentFor( $multiHandlers[0] ) );
		self::assertNotNull( ProtectedRoute::assignmentFor( $multiHandlers[1] ) );
		$multi = $this->server->dispatch( $multiRequest );
		// phpcs:ignore WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedHooknameFound -- Exercises the installed production Allow pass.
		$multi = apply_filters( 'rest_post_dispatch', $multi, $this->server, $multiRequest );
		self::assertInstanceOf( \WP_REST_Response::class, $multi );
		self::assertSame( 'GET', $multi->get_headers()['Allow'] );
		self::assertSame( 0, get_current_user_id() );

		try {
			$this->dispatchBearer( '/charter-test/v1/throwing', $token );
			self::fail( 'The protected fixture callback should throw.' );
		} catch ( \RuntimeException $exception ) {
			self::assertSame( 'charter_test_callback_failure', $exception->getMessage() );
		}
		self::assertSame( 0, get_current_user_id() );
		self::assertNull( Plugin::boot()->bearerAuthenticator()->currentContext() );
	}

	/**
	 * Verifies specialized MCP-compatible resource, scope, lifecycle, and fail-closed behavior.
	 */
	public function testSpecializedResourceAndScopeRemainExactThroughCredentialLifecycle(): void {
		$this->enableIssuer();
		$plugin           = Plugin::boot();
		$authorization    = $plugin->authorization();
		$parameters       = $this->mcpAuthorizationParameters( self::MCP_SCOPE . ' ' . AuthorizationService::OFFLINE_ACCESS_SCOPE );
		$serverMetadata   = $this->dispatch( 'GET', '/charter/v1/metadata/authorization-server' );
		$resourceMetadata = $this->dispatch( 'GET', '/charter/v1/metadata/protected-resource/wp-json/charter-test/v1/mcp' );
		self::assertContains( self::MCP_SCOPE, $serverMetadata->get_data()['scopes_supported'] );
		self::assertSame( $this->mcpResource(), $resourceMetadata->get_data()['resource'] );
		self::assertSame( array( self::MCP_SCOPE, self::MCP_MANAGE_SCOPE ), $resourceMetadata->get_data()['scopes_supported'] );

		$omittedScope = $parameters;
		unset( $omittedScope['scope'] );
		try {
			$authorization->validate( $omittedScope );
			self::fail( 'A specialized-only resource must not default to the general scope.' );
		} catch ( ProtocolException $exception ) {
			self::assertSame( 'invalid_scope', $exception->error() );
		}
		$generalScope          = $parameters;
		$generalScope['scope'] = AuthorizationService::GENERAL_SCOPE;
		try {
			$authorization->validate( $generalScope );
			self::fail( 'A specialized-only resource must reject the general scope.' );
		} catch ( ProtocolException $exception ) {
			self::assertSame( 'invalid_scope', $exception->error() );
		}

		$consent = $authorization->begin( $parameters, $this->userId );

		self::assertSame( $this->mcpResource(), $consent['request']->resource() );
		self::assertSame( self::MCP_SCOPE, $consent['request']->scope() );
		self::assertTrue( $consent['request']->continuingAccessRequested() );
		self::assertSame( 'Example MCP access', $consent['request']->consentScopes()[0]->name() );
		self::assertSame( 'Use the Example MCP server as your WordPress account.', $consent['request']->consentScopes()[0]->description() );
		$transactionRecord = $plugin->credentials()->find( CredentialStore::AUTHORIZATION_REQUEST, $this->issuer, $consent['transaction'] );
		self::assertNotNull( $transactionRecord );
		self::assertSame( $this->mcpResource(), $transactionRecord->resource() );
		self::assertSame( self::MCP_SCOPE, $transactionRecord->scope() );

		$code       = self::queryParameter(
			$authorization->complete( $consent['transaction'], $this->userId, true ),
			'code'
		);
		$codeRecord = $plugin->credentials()->find( CredentialStore::AUTHORIZATION_CODE, $this->issuer, $code );
		self::assertNotNull( $codeRecord );
		self::assertSame( $this->mcpResource(), $codeRecord->resource() );
		self::assertSame( self::MCP_SCOPE, $codeRecord->scope() );
		$wrongResource             = $this->mcpTokenParameters( $code );
		$wrongResource['resource'] = $this->issuer;
		try {
			$plugin->tokens()->exchange( $wrongResource );
			self::fail( 'An isolated-resource code must reject the default resource.' );
		} catch ( ProtocolException $exception ) {
			self::assertSame( 'invalid_target', $exception->error() );
		}

		$issued = $plugin->tokens()->exchange( $this->mcpTokenParameters( $code ) );
		self::assertSame( self::MCP_SCOPE, $issued['scope'] );
		self::assertSame( $this->mcpResource(), $issued['resource'] );
		self::assertIsString( $issued['refresh_token'] ?? null );

		$accessRecord  = $plugin->credentials()->find( CredentialStore::ACCESS_TOKEN, $this->issuer, $issued['access_token'] );
		$refreshRecord = $plugin->credentials()->find( CredentialStore::REFRESH_TOKEN, $this->issuer, $issued['refresh_token'] );
		self::assertNotNull( $accessRecord );
		self::assertNotNull( $refreshRecord );
		self::assertSame( $this->mcpResource(), $accessRecord->resource() );
		self::assertSame( self::MCP_SCOPE, $accessRecord->scope() );
		self::assertSame( $accessRecord->grantId(), $refreshRecord->grantId() );
		self::assertSame( $accessRecord->resource(), $refreshRecord->resource() );
		self::assertSame( $accessRecord->scope(), $refreshRecord->scope() );
		$grantId = $accessRecord->grantId();
		self::assertIsInt( $grantId );
		$activeGrant = $plugin->credentials()->findGrant( $grantId );
		self::assertNotNull( $activeGrant );
		self::assertSame( $this->mcpResource(), $activeGrant->resource() );
		self::assertSame( self::MCP_SCOPE, $activeGrant->scope() );

		$mcp = $this->dispatchBearer( '/charter-test/v1/mcp', $issued['access_token'] );
		self::assertSame( 200, $mcp->get_status() );
		self::assertSame( $this->userId, $mcp->get_data()['user_id'] );
		self::assertSame( $this->mcpResource(), $mcp->get_data()['resource'] );

		$defaultResource = $this->dispatchBearer( '/charter-test/v1/protected', $issued['access_token'] );
		self::assertSame( 401, $defaultResource->get_status() );

		$manageRequest = new WP_REST_Request( 'POST', '/charter-test/v1/mcp' );
		$manageRequest->set_header( 'Authorization', 'Bearer ' . $issued['access_token'] );
		$insufficient = $this->server->dispatch( $manageRequest );
		self::assertSame( 403, $insufficient->get_status() );
		self::assertSame(
			'Bearer error="insufficient_scope", scope="' . self::MCP_MANAGE_SCOPE . '", resource_metadata="' . ( new EndpointUrls( $this->issuer ) )->protectedResourceMetadata( $this->mcpResource() ) . '"',
			$insufficient->get_headers()['WWW-Authenticate']
		);

		$permissionConsent = $authorization->begin( $this->mcpAuthorizationParameters( self::MCP_MANAGE_SCOPE . ' ' . self::MCP_SCOPE ), $this->userId );
		self::assertSame( self::MCP_SCOPE . ' ' . self::MCP_MANAGE_SCOPE, $permissionConsent['request']->scope() );
		$permissionCode    = self::queryParameter(
			$authorization->complete( $permissionConsent['transaction'], $this->userId, true ),
			'code'
		);
		$permissionToken   = $plugin->tokens()->exchange( $this->mcpTokenParameters( $permissionCode ) );
		$permissionRequest = new WP_REST_Request( 'POST', '/charter-test/v1/mcp' );
		$permissionRequest->set_header( 'Authorization', 'Bearer ' . $permissionToken['access_token'] );
		$permissionDenied = $this->server->dispatch( $permissionRequest );
		self::assertSame( 403, $permissionDenied->get_status() );
		self::assertSame( 'rest_forbidden', $permissionDenied->get_data()['code'] );
		self::assertArrayNotHasKey( 'WWW-Authenticate', $permissionDenied->get_headers() );

		$reuse = $authorization->begin( $parameters, $this->userId );
		self::assertSame( $accessRecord->grantId(), $reuse['reusable_grant_id'] );

		$rotated = $plugin->tokens()->exchange(
			array(
				'grant_type'    => Client::GRANT_REFRESH_TOKEN,
				'client_id'     => self::MCP_CLIENT_ID,
				'refresh_token' => $issued['refresh_token'],
				'resource'      => $this->mcpResource(),
				'scope'         => self::MCP_SCOPE,
			)
		);
		self::assertSame( $this->mcpResource(), $rotated['resource'] );
		self::assertSame( self::MCP_SCOPE, $rotated['scope'] );
		self::assertIsString( $rotated['refresh_token'] ?? null );
		$rotatedAccessRecord  = $plugin->credentials()->find( CredentialStore::ACCESS_TOKEN, $this->issuer, $rotated['access_token'] );
		$rotatedRefreshRecord = $plugin->credentials()->find( CredentialStore::REFRESH_TOKEN, $this->issuer, $rotated['refresh_token'] );
		self::assertNotNull( $rotatedAccessRecord );
		self::assertNotNull( $rotatedRefreshRecord );
		self::assertSame( $this->mcpResource(), $rotatedAccessRecord->resource() );
		self::assertSame( self::MCP_SCOPE, $rotatedAccessRecord->scope() );
		self::assertSame( $this->mcpResource(), $rotatedRefreshRecord->resource() );
		self::assertSame( self::MCP_SCOPE, $rotatedRefreshRecord->scope() );
		self::assertSame( $refreshRecord->id(), $rotatedRefreshRecord->parentId() );

		$this->mcpProviderAvailable = false;
		$metadata                   = $this->dispatch( 'GET', '/charter/v1/metadata/protected-resource/wp-json/charter-test/v1/mcp' );
		self::assertSame( 404, $metadata->get_status() );
		$serverMetadata = $this->dispatch( 'GET', '/charter/v1/metadata/authorization-server' );
		self::assertNotContains( self::MCP_SCOPE, $serverMetadata->get_data()['scopes_supported'] );
		try {
			$authorization->validate( $parameters );
			self::fail( 'A missing specialized-resource provider must reject new authorization.' );
		} catch ( ProtocolException $exception ) {
			self::assertSame( 'invalid_target', $exception->error() );
		}
		self::assertSame( 401, $this->dispatchBearer( '/charter-test/v1/mcp', $rotated['access_token'] )->get_status() );
		try {
			$plugin->tokens()->exchange(
				array(
					'grant_type'    => Client::GRANT_REFRESH_TOKEN,
					'client_id'     => self::MCP_CLIENT_ID,
					'refresh_token' => $rotated['refresh_token'],
				)
			);
			self::fail( 'A missing specialized-scope provider must reject refresh.' );
		} catch ( ProtocolException $exception ) {
			self::assertSame( 'invalid_grant', $exception->error() );
		}

		$plugin->tokens()->revoke(
			array(
				'client_id' => self::MCP_CLIENT_ID,
				'token'     => $rotated['access_token'],
			)
		);
		$grant = $plugin->credentials()->findGrant( $grantId );
		self::assertNotNull( $grant );
		self::assertSame( 'revoked', $grant->status() );
	}

	/**
	 * Registers the simulated MCP server-wide resource and scopes.
	 *
	 * @param AccessPolicy $policy Exact issuer policy under construction.
	 * @param string       $issuer Exact current issuer.
	 */
	public function registerMcpAccess( AccessPolicy $policy, string $issuer ): void {
		if ( ! $this->mcpProviderAvailable ) {
			return;
		}

		$resource = $issuer . '/wp-json/charter-test/v1/mcp';
		self::assertTrue( $policy->registerResource( 'example-mcp', $resource ) );
		self::assertTrue( $policy->registerScope( 'example-mcp', self::MCP_SCOPE, 'Example MCP access', 'Use the Example MCP server as your WordPress account.', array( $resource ) ) );
		self::assertTrue( $policy->registerScope( 'example-mcp', self::MCP_MANAGE_SCOPE, 'Example MCP management', 'Use management operations exposed by the Example MCP server.', array( $resource ) ) );
	}

	/**
	 * Registers public and exact-handler-protected test integrations.
	 *
	 * @since 0.1.0
	 */
	public function registerTestRoutes(): void {
		register_rest_route(
			'charter-test/v1',
			'/public',
			array(
				'methods'             => 'GET',
				'permission_callback' => '__return_true',
				'callback'            => static fn (): array => array( 'public' => true ),
			)
		);

		register_rest_route(
			'charter-test/v1',
			'/protected',
			ProtectedRoute::assign(
				array(
					'methods'             => 'GET',
					'permission_callback' => static fn (): bool => current_user_can( 'read' ),
					'callback'            => static function (): array {
						$context = Plugin::boot()->bearerAuthenticator()->currentContext();

						return array(
							'user_id'   => get_current_user_id(),
							'client_id' => null === $context ? null : $context->clientId(),
							'resource'  => null === $context ? null : $context->resource(),
						);
					},
				)
			)
		);

		register_rest_route(
			'charter-test/v1',
			'/mcp',
			array(
				ProtectedRoute::assign(
					array(
						'methods'             => 'GET',
						'permission_callback' => static fn (): bool => current_user_can( 'read' ),
						'callback'            => static function (): array {
							$context = Plugin::boot()->bearerAuthenticator()->currentContext();

							return array(
								'user_id'  => get_current_user_id(),
								'resource' => null === $context ? null : $context->resource(),
							);
						},
					),
					array( self::MCP_SCOPE ),
					$this->mcpResource()
				),
				ProtectedRoute::assign(
					array(
						'methods'             => 'POST',
						'permission_callback' => static fn (): bool => current_user_can( 'manage_options' ),
						'callback'            => '__return_empty_array',
					),
					array( self::MCP_MANAGE_SCOPE ),
					$this->mcpResource()
				),
			)
		);

		register_rest_route(
			'charter-test/v1',
			'/other-resource',
			ProtectedRoute::assign(
				array(
					'methods'             => 'GET',
					'permission_callback' => '__return_true',
					'callback'            => '__return_empty_array',
				),
				array( AuthorizationService::GENERAL_SCOPE ),
				$this->issuer . '/other'
			)
		);

		register_rest_route(
			'charter-test/v1',
			'/admin-only',
			ProtectedRoute::assign(
				array(
					'methods'             => 'GET',
					'permission_callback' => static fn (): bool => current_user_can( 'manage_options' ),
					'callback'            => '__return_empty_array',
				)
			)
		);

		register_rest_route(
			'charter-test/v1',
			'/throwing',
			ProtectedRoute::assign(
				array(
					'methods'             => 'GET',
					'permission_callback' => '__return_true',
					'callback'            => static function (): never {
						throw new \RuntimeException( 'charter_test_callback_failure' );
					},
				)
			)
		);

		register_rest_route(
			'charter-test/v1',
			'/nested',
			ProtectedRoute::assign(
				array(
					'methods'             => 'GET',
					'permission_callback' => '__return_true',
					'callback'            => function (): array {
						$inner   = $this->dispatch( 'GET', '/charter-test/v1/other-resource' );
						$context = Plugin::boot()->bearerAuthenticator()->currentContext();

						return array(
							'inner_status'    => $inner->get_status(),
							'outer_user_id'   => get_current_user_id(),
							'outer_client_id' => null === $context ? null : $context->clientId(),
						);
					},
				)
			)
		);

		register_rest_route(
			'charter-test/v1',
			'/multi',
			array(
				ProtectedRoute::assign(
					array(
						'methods'             => 'GET',
						'permission_callback' => '__return_true',
						'callback'            => static fn (): array => array( 'method' => 'GET' ),
					)
				),
				ProtectedRoute::assign(
					array(
						'methods'             => 'POST',
						'permission_callback' => '__return_true',
						'callback'            => static fn (): array => array( 'method' => 'POST' ),
					),
					array( AuthorizationService::GENERAL_SCOPE ),
					$this->issuer . '/other'
				),
			)
		);
	}

	/**
	 * Enables the exact prepared issuer through its verification transition.
	 *
	 * @since 0.1.0
	 */
	private function enableIssuer(): void {
		$state = Plugin::boot()->siteState();
		self::assertTrue( $state->recordDiscoveryVerification( $this->issuer ) );
		self::assertTrue( $state->enable( $this->issuer ) );
	}

	/**
	 * Starts and approves one authorization request.
	 *
	 * @since 0.1.0
	 */
	private function authorizeCode(): string {
		$authorization = Plugin::boot()->authorization();
		$consent       = $authorization->begin( $this->authorizationParameters(), $this->userId );
		$redirect      = $authorization->complete( $consent['transaction'], $this->userId, true );
		$query         = wp_parse_url( $redirect, PHP_URL_QUERY );
		self::assertIsString( $query );
		parse_str( $query, $parameters );

		self::assertSame( 'client-state', $parameters['state'] ?? null );
		self::assertSame( $this->issuer, $parameters['iss'] ?? null );
		self::assertIsString( $parameters['code'] ?? null );

		return $parameters['code'];
	}

	/**
	 * Issues one access token through the real token REST controller.
	 *
	 * @since 0.1.0
	 */
	private function issueAccessToken(): string {
		$response = $this->exchangeCode( $this->authorizeCode() );
		self::assertSame( 200, $response->get_status() );
		self::assertIsString( $response->get_data()['access_token'] ?? null );

		return $response->get_data()['access_token'];
	}

	/**
	 * Issues one access token for an exact represented test user.
	 *
	 * @since 0.1.0
	 *
	 * @param int $userId Represented WordPress user.
	 */
	private function issueAccessTokenForUser( int $userId ): string {
		$authorization = Plugin::boot()->authorization();
		$consent       = $authorization->begin( $this->authorizationParameters(), $userId );
		$code          = self::queryParameter(
			$authorization->complete( $consent['transaction'], $userId, true ),
			'code'
		);
		$response      = $this->exchangeCode( $code );
		self::assertSame( 200, $response->get_status() );
		$data = $response->get_data();
		self::assertIsString( $data['access_token'] ?? null );

		return $data['access_token'];
	}

	/**
	 * Exchanges a code with optional parameter overrides.
	 *
	 * @since 0.1.0
	 *
	 * @param string               $code      Authorization code.
	 * @param array<string, mixed> $overrides Parameter overrides.
	 */
	private function exchangeCode( string $code, array $overrides = array() ): \WP_REST_Response {
		$request = new WP_REST_Request( 'POST', '/charter/v1/token' );
		$request->set_header( 'Content-Type', 'application/x-www-form-urlencoded' );
		$request->set_body_params(
			array_replace(
				array(
					'grant_type'    => 'authorization_code',
					'client_id'     => self::CLIENT_ID,
					'code'          => $code,
					'code_verifier' => self::VERIFIER,
					'redirect_uri'  => self::REDIRECT_URI,
					'resource'      => $this->issuer,
				),
				$overrides
			)
		);

		return $this->server->dispatch( $request );
	}

	/**
	 * Dispatches one exact form-encoded token request.
	 *
	 * @since 0.1.0
	 *
	 * @param array<string, string> $parameters Token request parameters.
	 */
	private function dispatchToken( array $parameters ): \WP_REST_Response {
		$request = new WP_REST_Request( 'POST', '/charter/v1/token' );
		$request->set_header( 'Content-Type', 'application/x-www-form-urlencoded' );
		$request->set_body_params( $parameters );

		return $this->server->dispatch( $request );
	}

	/**
	 * Dispatches one exact form-encoded token revocation request.
	 *
	 * @since 0.1.0
	 *
	 * @param array<string, string> $parameters Revocation request parameters.
	 */
	private function dispatchRevocation( array $parameters ): \WP_REST_Response {
		$request = new WP_REST_Request( 'POST', '/charter/v1/revoke' );
		$request->set_header( 'Content-Type', 'application/x-www-form-urlencoded' );
		$request->set_body_params( $parameters );

		return $this->server->dispatch( $request );
	}

	/**
	 * Dispatches one confidential-client refresh request.
	 *
	 * @since 0.1.0
	 *
	 * @param string                $refreshToken Presented refresh token.
	 * @param string                $clientSecret Confidential client secret.
	 * @param array<string, string> $overrides Exact parameter overrides.
	 */
	private function dispatchRefresh( string $refreshToken, string $clientSecret, array $overrides = array() ): \WP_REST_Response {
		return $this->dispatchToken(
			array_replace(
				array(
					'grant_type'    => Client::GRANT_REFRESH_TOKEN,
					'client_id'     => self::CONFIDENTIAL_CLIENT_ID,
					'client_secret' => $clientSecret,
					'refresh_token' => $refreshToken,
					'resource'      => $this->issuer,
				),
				$overrides
			)
		);
	}

	/**
	 * Returns one required scalar callback query parameter.
	 *
	 * @since 0.1.0
	 *
	 * @param string $url Redirect URL.
	 * @param string $name Query parameter name.
	 */
	private static function queryParameter( string $url, string $name ): string {
		$query = wp_parse_url( $url, PHP_URL_QUERY );
		self::assertIsString( $query );
		parse_str( $query, $parameters );
		$value = $parameters[ $name ] ?? null;
		self::assertIsString( $value );

		return $value;
	}

	/**
	 * Returns one complete valid public-client authorization request.
	 *
	 * @since 0.1.0
	 *
	 * @return array<string, string> Request parameters.
	 */
	private function authorizationParameters(): array {
		return array(
			'response_type'         => 'code',
			'client_id'             => self::CLIENT_ID,
			'redirect_uri'          => self::REDIRECT_URI,
			'code_challenge'        => TokenService::s256Challenge( self::VERIFIER ),
			'code_challenge_method' => 'S256',
			'resource'              => $this->issuer,
			'scope'                 => AuthorizationService::GENERAL_SCOPE,
			'state'                 => 'client-state',
		);
	}

	/** Returns the exact isolated MCP resource for the current issuer. */
	private function mcpResource(): string {
		return $this->issuer . '/wp-json/charter-test/v1/mcp';
	}

	/**
	 * Returns one complete MCP-compatible authorization request.
	 *
	 * @param string $scope Requested scope parameter.
	 * @return array<string, string> Request parameters.
	 */
	private function mcpAuthorizationParameters( string $scope ): array {
		return array(
			'response_type'         => 'code',
			'client_id'             => self::MCP_CLIENT_ID,
			'redirect_uri'          => self::MCP_REDIRECT_URI,
			'code_challenge'        => TokenService::s256Challenge( self::VERIFIER ),
			'code_challenge_method' => 'S256',
			'resource'              => $this->mcpResource(),
			'scope'                 => $scope,
			'state'                 => 'mcp-client-state',
		);
	}

	/**
	 * Returns one exact MCP-compatible authorization-code exchange.
	 *
	 * @param string $code Exact authorization code.
	 * @return array<string, string> Token parameters.
	 */
	private function mcpTokenParameters( string $code ): array {
		return array(
			'grant_type'    => Client::GRANT_AUTHORIZATION_CODE,
			'client_id'     => self::MCP_CLIENT_ID,
			'code'          => $code,
			'code_verifier' => self::VERIFIER,
			'redirect_uri'  => self::MCP_REDIRECT_URI,
			'resource'      => $this->mcpResource(),
		);
	}

	/**
	 * Counts only persisted registrations, grants, and credential/consent rows.
	 *
	 * @return array{clients:int,grants:int,credentials:int}
	 */
	private function oauthStateCounts(): array {
		global $wpdb;

		return array(
			'clients'     => (int) $wpdb->get_var( 'SELECT COUNT(*) FROM ' . Schema::clientTable() ), // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching,WordPress.DB.PreparedSQL.NotPrepared -- Test-only count over a fixed production table.
			'grants'      => (int) $wpdb->get_var( 'SELECT COUNT(*) FROM ' . Schema::grantTable() ), // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching,WordPress.DB.PreparedSQL.NotPrepared -- Test-only count over a fixed production table.
			'credentials' => (int) $wpdb->get_var( 'SELECT COUNT(*) FROM ' . Schema::credentialTable() ), // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching,WordPress.DB.PreparedSQL.NotPrepared -- Test-only count over a fixed production table.
		);
	}

	/**
	 * Dispatches a simple REST request.
	 *
	 * @since 0.1.0
	 *
	 * @param string $method HTTP method.
	 * @param string $route  REST route.
	 */
	private function dispatch( string $method, string $route ): \WP_REST_Response {
		return $this->server->dispatch( new WP_REST_Request( $method, $route ) );
	}

	/**
	 * Dispatches a REST request with one Bearer credential.
	 *
	 * @since 0.1.0
	 *
	 * @param string $route REST route.
	 * @param string $token Bearer credential.
	 */
	private function dispatchBearer( string $route, string $token ): \WP_REST_Response {
		$request = new WP_REST_Request( 'GET', $route );
		$request->set_header( 'Authorization', 'Bearer ' . $token );

		return $this->server->dispatch( $request );
	}
}
