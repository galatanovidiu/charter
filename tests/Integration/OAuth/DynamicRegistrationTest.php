<?php
/**
 * Dynamic Client Registration and administrator governance integration tests.
 *
 * @package GalatanOvidiu\Charter
 */

declare(strict_types=1);

namespace GalatanOvidiu\Charter\Tests\Integration\OAuth;

use GalatanOvidiu\Charter\Http\EndpointUrls;
use GalatanOvidiu\Charter\OAuth\AuthorizationService;
use GalatanOvidiu\Charter\OAuth\Client;
use GalatanOvidiu\Charter\OAuth\ClientRegistry;
use GalatanOvidiu\Charter\OAuth\DynamicRegistrationService;
use GalatanOvidiu\Charter\OAuth\ProtocolException;
use GalatanOvidiu\Charter\OAuth\TokenService;
use GalatanOvidiu\Charter\OAuth\TransactionManager;
use GalatanOvidiu\Charter\Plugin;
use GalatanOvidiu\Charter\Schema;
use mysqli;
use RuntimeException;
use WP_REST_Request;
use WP_REST_Server;
use WP_UnitTestCase;

/**
 * Exercises anonymous DCR policy, immutable clients, and cascading governance.
 *
 * @since 0.1.0
 */
final class DynamicRegistrationTest extends WP_UnitTestCase {

	private const REDIRECT = 'https://dynamic.example.test/callback';
	private const VERIFIER = '0123456789abcdefghijklmnopqrstuvwxyzABCDEFG';

	/**
	 * Isolated REST server.
	 *
	 * @var WP_REST_Server
	 */
	private WP_REST_Server $server;

	/**
	 * Exact current issuer.
	 *
	 * @var string
	 */
	private string $issuer;

	/**
	 * Prior direct peer fixture.
	 *
	 * @var mixed
	 */
	private mixed $previousRemoteAddress;

	/** Installs persistent tables before Core test transactions. */
	public static function set_up_before_class(): void {
		parent::set_up_before_class();
		Schema::install();
	}

	/** Creates isolated enabled issuer, persistence, and REST state. */
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
		delete_option( 'charter_oauth_dcr_enabled' );
		delete_option( 'charter_oauth_last_cleanup_at' );
		self::assertTrue( $plugin->siteState()->prepareCurrentSite() );
		$identity = $plugin->siteState()->identity();
		self::assertNotNull( $identity );
		$this->issuer = $identity->issuer();
		self::assertTrue( $plugin->siteState()->recordDiscoveryVerification( $this->issuer ) );
		self::assertTrue( $plugin->siteState()->enable( $this->issuer ) );

		$this->previousRemoteAddress = $_SERVER['REMOTE_ADDR'] ?? null;
		$_SERVER['REMOTE_ADDR']      = '203.0.113.40';
		global $wp_rest_server; // phpcs:ignore WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedVariableFound -- Core-owned REST server global.
		$wp_rest_server = new WP_REST_Server(); // phpcs:ignore WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedVariableFound -- Isolated integration REST server.
		do_action( 'rest_api_init', $wp_rest_server ); // phpcs:ignore WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedHooknameFound -- Registers production routes in the isolated server.
		$this->server = $wp_rest_server;
	}

	/** Removes all current-site OAuth fixture state. */
	public function tear_down(): void {
		$plugin = Plugin::boot();
		$plugin->credentials()->deleteAll();
		$plugin->clients()->deleteAll();
		$plugin->clientMetadataSnapshots()->deleteAll();
		$plugin->audit()->deleteAll();
		$plugin->rateLimiter()->deleteAll();
		$plugin->siteState()->delete();
		delete_option( 'charter_oauth_dcr_enabled' );
		delete_option( 'charter_oauth_last_cleanup_at' );
		if ( null === $this->previousRemoteAddress ) {
			unset( $_SERVER['REMOTE_ADDR'] );
		} else {
			$_SERVER['REMOTE_ADDR'] = $this->previousRemoteAddress;
		}
		wp_set_current_user( 0 );
		parent::tear_down();
	}

	/**
	 * Verifies default advertisement and a secret-free public registration.
	 */
	public function testPublicDynamicRegistrationIsAdvertisedAndImmutable(): void {
		$metadata = $this->dispatch( 'GET', '/charter/v1/metadata/authorization-server' );
		self::assertSame( ( new EndpointUrls( $this->issuer ) )->registrationEndpoint(), $metadata->get_data()['registration_endpoint'] );

		$response = $this->registerClient( Client::AUTH_NONE, true );
		self::assertSame( 201, $response->get_status() );
		$data = $response->get_data();
		self::assertIsString( $data['client_id'] ?? null );
		self::assertStringStartsWith( 'chd_', $data['client_id'] );
		self::assertArrayNotHasKey( 'client_secret', $data );
		self::assertSame( 'no-store', $response->get_headers()['Cache-Control'] );
		self::assertArrayNotHasKey( 'Access-Control-Allow-Origin', $response->get_headers() );

		$client = Plugin::boot()->clients()->findActive( $this->issuer, $data['client_id'] );
		self::assertNotNull( $client );
		self::assertSame( ClientRegistry::SOURCE_DYNAMIC, $client->source() );
		self::assertTrue( $client->supportsGrantType( Client::GRANT_REFRESH_TOKEN ) );
		self::assertSame( self::REDIRECT, $client->redirectUris()[0] );
	}

	/**
	 * Verifies confidential DCR is explicit and stores only a password hash.
	 */
	public function testConfidentialRegistrationRevealsSecretOnceAndRejectsDefaults(): void {
		$missingMethod = $this->registrationRequest(
			array(
				'client_name'   => 'Missing method',
				'redirect_uris' => array( self::REDIRECT ),
			)
		);
		self::assertSame( 400, $missingMethod->get_status() );
		self::assertSame( 'invalid_client_metadata', $missingMethod->get_data()['error'] );

		$duplicateMethod = $this->rawRegistrationRequest(
			'{"client_name":"Duplicate","redirect_uris":["https://dynamic.example.test/callback"],"token_endpoint_auth_method":"none","token_endpoint_auth_method":"client_secret_post"}'
		);
		self::assertSame( 400, $duplicateMethod->get_status() );

		$response = $this->registerClient( Client::AUTH_CLIENT_SECRET_POST, true );
		self::assertSame( 201, $response->get_status() );
		$data = $response->get_data();
		self::assertIsString( $data['client_secret'] ?? null );
		self::assertStringStartsWith( 'chs_', $data['client_secret'] );
		self::assertSame( 0, $data['client_secret_expires_at'] );

		global $wpdb;
		$rows    = $wpdb->get_results( 'SELECT client_secret_hash FROM ' . Schema::clientTable(), ARRAY_A ); // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching,WordPress.DB.PreparedSQL.NotPrepared -- Test-only inspection of the fixed table.
		$encoded = wp_json_encode( $rows );
		self::assertIsString( $encoded );
		self::assertStringNotContainsString( $data['client_secret'], $encoded );
	}

	/**
	 * Verifies operator stopping does not revoke existing registrations.
	 */
	public function testStoppingDynamicRegistrationRemovesAdvertisementOnly(): void {
		$registered = $this->registerClient( Client::AUTH_NONE, false )->get_data();
		self::assertTrue( DynamicRegistrationService::setEnabled( false ) );

		$metadata = $this->dispatch( 'GET', '/charter/v1/metadata/authorization-server' );
		self::assertArrayNotHasKey( 'registration_endpoint', $metadata->get_data() );
		$stopped = $this->registerClient( Client::AUTH_NONE, false );
		self::assertSame( 403, $stopped->get_status() );
		self::assertNotNull( Plugin::boot()->clients()->findActive( $this->issuer, $registered['client_id'] ) );
	}

	/**
	 * Verifies the exact DCR defaults use rate-limited non-revealing responses.
	 */
	public function testDynamicRegistrationRateLimitUsesRetryAfter(): void {
		for ( $request = 1; $request <= 5; ++$request ) {
			self::assertSame( 201, $this->registerClient( Client::AUTH_NONE, false )->get_status() );
		}

		$limited = $this->registerClient( Client::AUTH_NONE, false );
		self::assertSame( 429, $limited->get_status() );
		self::assertSame( 'temporarily_unavailable', $limited->get_data()['error'] );
		self::assertMatchesRegularExpression( '/^[1-9][0-9]*$/D', $limited->get_headers()['Retry-After'] );
		self::assertCount( 6, Plugin::boot()->audit()->listForIssuer( $this->issuer ) );
	}

	/**
	 * Verifies block and delete actions close all descendants immediately.
	 */
	public function testAdministratorBlockAndDeleteCascadeAcrossClientGrants(): void {
		$data     = $this->registerClient( Client::AUTH_NONE, true )->get_data();
		$clientId = $data['client_id'];
		$userId   = self::factory()->user->create( array( 'role' => 'subscriber' ) );
		$code     = $this->authorizeCode( $clientId, $userId );
		$this->setClientLifecycle( $clientId, null, 1 );
		$tokens = Plugin::boot()->tokens()->exchange(
			array(
				'grant_type'    => Client::GRANT_AUTHORIZATION_CODE,
				'client_id'     => $clientId,
				'code'          => $code,
				'code_verifier' => self::VERIFIER,
			)
		);
		self::assertIsString( $tokens['access_token'] );
		self::assertIsString( $tokens['refresh_token'] ?? null );
		self::assertCount( 1, Plugin::boot()->credentials()->listActiveGrantsForClient( $this->issuer, $clientId ) );
		self::assertGreaterThan( 1, Plugin::boot()->clients()->listForIssuer( $this->issuer )[0]->lastActivityAt() );

		self::assertTrue( Plugin::boot()->clientGovernance()->block( $this->issuer, $clientId, 1, time() ) );
		self::assertNull( Plugin::boot()->clients()->findActive( $this->issuer, $clientId ) );
		self::assertSame( array(), Plugin::boot()->credentials()->listActiveGrantsForClient( $this->issuer, $clientId ) );
		try {
			Plugin::boot()->tokens()->validateAccessToken( $tokens['access_token'], $this->issuer, array( AuthorizationService::GENERAL_SCOPE ) );
			self::fail( 'A blocked client access token must fail immediately.' );
		} catch ( ProtocolException $exception ) {
			self::assertSame( 'invalid_token', $exception->error() );
		}

		self::assertTrue( Plugin::boot()->clientGovernance()->delete( $this->issuer, $clientId, 1, time() ) );
		$records = Plugin::boot()->clients()->listForIssuer( $this->issuer );
		self::assertSame( ClientRegistry::STATUS_DELETED, $records[0]->status() );
		self::assertSame( array(), $records[0]->redirectUris() );
		self::assertCount( 3, Plugin::boot()->audit()->listForIssuer( $this->issuer ) );
	}

	/**
	 * Verifies abandoned DCR cleanup is bounded by age and active grants.
	 */
	public function testAbandonedDynamicRegistrationLifecyclePreservesActiveGrants(): void {
		$unusedId = $this->registerClient( Client::AUTH_NONE, false )->get_data()['client_id'];
		$activeId = $this->registerClient( Client::AUTH_NONE, false )->get_data()['client_id'];
		$userId   = self::factory()->user->create( array( 'role' => 'subscriber' ) );
		$this->authorizeCode( $activeId, $userId );

		$old = time() - 91 * DAY_IN_SECONDS;
		$this->setClientLifecycle( $unusedId, $old, $old );
		$this->setClientLifecycle( $activeId, null, $old );

		$candidates   = Plugin::boot()->clients()->findAbandonedDynamicClients( $this->issuer, time() );
		$candidateIds = array_map( static fn ( $record ): string => $record->clientId(), $candidates );
		self::assertContains( $unusedId, $candidateIds );
		self::assertContains( $activeId, $candidateIds );
		self::assertTrue( Plugin::boot()->clientGovernance()->deleteAbandoned( $this->issuer, $unusedId, time() ) );
		self::assertFalse( Plugin::boot()->clientGovernance()->deleteAbandoned( $this->issuer, $activeId, time() ) );
		self::assertNull( Plugin::boot()->clients()->findActive( $this->issuer, $unusedId ) );
		self::assertNotNull( Plugin::boot()->clients()->findActive( $this->issuer, $activeId ) );
	}

	/**
	 * Adjusts lifecycle timestamps through the same owned connection boundary as production.
	 *
	 * @param string   $clientId Exact client identifier.
	 * @param int|null $createdAt Optional creation timestamp.
	 * @param int      $lastActivityAt Activity timestamp.
	 */
	private function setClientLifecycle( string $clientId, ?int $createdAt, int $lastActivityAt ): void {
		( new TransactionManager() )->run(
			static function ( mysqli $database ) use ( $clientId, $createdAt, $lastActivityAt ): void {
				$table      = '`' . str_replace( '`', '``', Schema::clientTable() ) . '`';
				$assignment = null === $createdAt ? 'last_activity_at = ?' : 'created_at = ?, last_activity_at = ?';
				$parameters = null === $createdAt ? array( $lastActivityAt, $clientId ) : array( $createdAt, $lastActivityAt, $clientId );
				$result     = $database->execute_query(
					"UPDATE {$table} SET {$assignment} WHERE client_id = ?",
					$parameters
				); // phpcs:ignore WordPress.DB.RestrictedFunctions.mysql_mysqli -- Test fixture uses the production-owned transaction boundary.
				if ( true !== $result || 1 !== $database->affected_rows ) {
					throw new RuntimeException( 'charter_test_client_lifecycle_update_failed' );
				}
			}
		);
	}

	/**
	 * Completes consent and returns one code.
	 *
	 * @param string $clientId Exact client identifier.
	 * @param int    $userId Represented user.
	 */
	private function authorizeCode( string $clientId, int $userId ): string {
		$consent  = Plugin::boot()->authorization()->begin(
			array(
				'response_type'         => 'code',
				'client_id'             => $clientId,
				'redirect_uri'          => self::REDIRECT,
				'code_challenge'        => TokenService::s256Challenge( self::VERIFIER ),
				'code_challenge_method' => 'S256',
				'resource'              => $this->issuer,
				'scope'                 => AuthorizationService::GENERAL_SCOPE . ' ' . AuthorizationService::OFFLINE_ACCESS_SCOPE,
				'state'                 => 'dynamic-state',
			),
			$userId
		);
		$redirect = Plugin::boot()->authorization()->complete( $consent['transaction'], $userId, true );
		parse_str( (string) wp_parse_url( $redirect, PHP_URL_QUERY ), $parameters );
		self::assertIsString( $parameters['code'] ?? null );

		return $parameters['code'];
	}

	/**
	 * Registers one test client.
	 *
	 * @param string $method Token authentication method.
	 * @param bool   $refresh Whether refresh is declared.
	 */
	private function registerClient( string $method, bool $refresh ): \WP_REST_Response {
		$grantTypes = array( Client::GRANT_AUTHORIZATION_CODE );
		if ( $refresh ) {
			$grantTypes[] = Client::GRANT_REFRESH_TOKEN;
		}

		return $this->registrationRequest(
			array(
				'client_name'                => 'Dynamic integration client',
				'redirect_uris'              => array( self::REDIRECT ),
				'token_endpoint_auth_method' => $method,
				'grant_types'                => $grantTypes,
				'response_types'             => array( 'code' ),
			)
		);
	}

	/**
	 * Dispatches structured registration metadata.
	 *
	 * @param array<string,mixed> $metadata Registration metadata.
	 */
	private function registrationRequest( array $metadata ): \WP_REST_Response {
		$body = wp_json_encode( $metadata );
		self::assertIsString( $body );

		return $this->rawRegistrationRequest( $body );
	}

	/**
	 * Dispatches one raw registration body.
	 *
	 * @param string $body Complete JSON body.
	 */
	private function rawRegistrationRequest( string $body ): \WP_REST_Response {
		$request = new WP_REST_Request( 'POST', '/charter/v1/register' );
		$request->set_header( 'Content-Type', 'application/json' );
		$request->set_body( $body );
		$response = $this->server->dispatch( $request );
		self::assertInstanceOf( \WP_REST_Response::class, $response );

		return $response;
	}

	/**
	 * Dispatches one ordinary REST request.
	 *
	 * @param string $method HTTP method.
	 * @param string $route REST route.
	 */
	private function dispatch( string $method, string $route ): \WP_REST_Response {
		$response = $this->server->dispatch( new WP_REST_Request( $method, $route ) );
		self::assertInstanceOf( \WP_REST_Response::class, $response );

		return $response;
	}
}
