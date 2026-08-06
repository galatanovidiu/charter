<?php
/**
 * First working OAuth path integration tests.
 *
 * @package GalatanOvidiu\Charter
 */

declare(strict_types=1);

namespace GalatanOvidiu\Charter\Tests\Integration\OAuth;

use GalatanOvidiu\Charter\Http\EndpointUrls;
use GalatanOvidiu\Charter\OAuth\AuthorizationService;
use GalatanOvidiu\Charter\OAuth\Client;
use GalatanOvidiu\Charter\OAuth\CredentialStore;
use GalatanOvidiu\Charter\OAuth\ProtocolException;
use GalatanOvidiu\Charter\OAuth\TokenService;
use GalatanOvidiu\Charter\OAuth\TransactionManager;
use GalatanOvidiu\Charter\Plugin;
use GalatanOvidiu\Charter\Rest\ProtectedRoute;
use GalatanOvidiu\Charter\Schema;
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
		$plugin = Plugin::boot();
		$plugin->credentials()->deleteAll();
		$plugin->clients()->deleteAll();
		$plugin->clientMetadataSnapshots()->deleteAll();
		$plugin->audit()->deleteAll();
		$plugin->rateLimiter()->deleteAll();
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

		$scope = $this->dispatchBearer( '/charter-test/v1/specialized', $token );
		self::assertSame( 403, $scope->get_status() );
		self::assertSame( 'Bearer error="insufficient_scope", scope="example:special"', $scope->get_headers()['WWW-Authenticate'] );

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
			'/specialized',
			ProtectedRoute::assign(
				array(
					'methods'             => 'GET',
					'permission_callback' => '__return_true',
					'callback'            => '__return_empty_array',
				),
				array( 'example:special' )
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
