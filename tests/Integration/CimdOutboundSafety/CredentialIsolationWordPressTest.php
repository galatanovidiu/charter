<?php
/**
 * Retained P2 protected-request isolation proof for P3.
 *
 * @package GalatanOvidiu\Charter
 */

declare(strict_types=1);

namespace GalatanOvidiu\Charter\Tests\Integration\CimdOutboundSafety;

use GalatanOvidiu\Charter\Tests\Prototype\CimdOutboundSafety\AuthorizationBoundary as CimdAuthorizationBoundary;
use GalatanOvidiu\Charter\Tests\Prototype\CimdOutboundSafety\CredentialPathProbe;
use GalatanOvidiu\Charter\Tests\Prototype\RestAuthenticationBoundary\ProtectedRouteRegistry;
use GalatanOvidiu\Charter\Tests\Prototype\RestAuthenticationBoundary\RestAuthenticationBoundary;
use GalatanOvidiu\Charter\Tests\Prototype\RestAuthenticationBoundary\SyntheticBearerFixtures;
use PHPUnit\Framework\TestCase;
use WP_REST_Request;
use WP_REST_Server;

// Exactly one of the bootstrap-specific test classes is declared at runtime.
// phpcs:disable Generic.Files.OneObjectStructurePerFile.MultipleFound
// phpcs:disable Generic.Classes.DuplicateClassName.Found

if ( ! class_exists( '\WP_UnitTestCase' ) ) {
	/**
	 * Keeps the pure P3 matrix explicit; the P3 runner executes the real WordPress lane.
	 *
	 * @since 0.1.0
	 */
	final class CredentialIsolationWordPressTest extends TestCase {

		/** Skips outside the exact retained P2 WordPress bootstrap. */
		public function testRequiresTheRetainedP2WordPressBootstrap(): void {
			self::markTestSkipped( 'The retained P2 WordPress bootstrap is required.' );
		}
	}
} else {
	/**
	 * Proves a real retained-P2 protected REST dispatch has no CIMD dependency.
	 *
	 * @since 0.1.0
	 */
	final class CredentialIsolationWordPressTest extends \WP_UnitTestCase {

		private const ROUTE = '/charter-p3-isolation/v1/protected';

		/**
		 * Retained P2 boundary.
		 *
		 * @var RestAuthenticationBoundary
		 */
		private RestAuthenticationBoundary $restBoundary;

		/**
		 * Process-local retained P2 bearer fixtures.
		 *
		 * @var SyntheticBearerFixtures
		 */
		private SyntheticBearerFixtures $fixtures;

		/**
		 * Isolated WordPress REST server.
		 *
		 * @var WP_REST_Server
		 */
		private WP_REST_Server $server;

		/**
		 * Prior Core REST server.
		 *
		 * @var WP_REST_Server|null
		 */
		private ?WP_REST_Server $priorServer = null;

		/**
		 * Prior WordPress user ID.
		 *
		 * @var int
		 */
		private int $priorUserId = 0;

		/**
		 * Installs one retained P2 protected route in disposable WordPress state.
		 */
		public function setUp(): void {
			parent::setUp();

			$this->priorServer  = isset( $GLOBALS['wp_rest_server'] ) && $GLOBALS['wp_rest_server'] instanceof WP_REST_Server
				? $GLOBALS['wp_rest_server']
				: null;
			$this->priorUserId  = get_current_user_id();
			$userA              = self::factory()->user->create( array( 'role' => 'administrator' ) );
			$userB              = self::factory()->user->create( array( 'role' => 'subscriber' ) );
			$this->server       = new WP_REST_Server();
			$this->fixtures     = new SyntheticBearerFixtures( $userA, $userB );
			$this->restBoundary = RestAuthenticationBoundary::fromFixtures( $this->fixtures );

			// phpcs:ignore WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedVariableFound -- Core REST server global.
			$GLOBALS['wp_rest_server'] = $this->server;
			add_filter( 'rest_pre_dispatch', 'rest_handle_options_request', 10, 3 );
			$this->restBoundary->install();

			$handler = ProtectedRouteRegistry::assign(
				array(
					'methods'             => 'GET',
					'permission_callback' => '__return_true',
					'callback'            => static fn (): array => array( 'protected' => true ),
				),
				'p3_credential_isolation',
				SyntheticBearerFixtures::DEFAULT_RESOURCE,
				array( SyntheticBearerFixtures::GENERAL_SCOPE )
			);
			$this->server->register_route(
				'charter-p3-isolation/v1',
				self::ROUTE,
				array( $handler )
			);
		}

		/** Removes exact P2 hooks and restores prior WordPress state. */
		public function tearDown(): void {
			$this->restBoundary->remove();
			$this->restBoundary->reset();
			remove_filter( 'rest_pre_dispatch', 'rest_handle_options_request', 10 );
			wp_set_current_user( $this->priorUserId );

			if ( $this->priorServer instanceof WP_REST_Server ) {
				// phpcs:ignore WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedVariableFound -- Restores Core REST server global.
				$GLOBALS['wp_rest_server'] = $this->priorServer;
			} else {
				unset( $GLOBALS['wp_rest_server'] );
			}

			parent::tearDown();
		}

		/**
		 * Verifies outage of new-authorization metadata cannot affect a real P2 request.
		 */
		public function testProtectedP2DispatchRemainsLocalWhenNewAuthorizationFails(): void {
			$cimd        = new CimdAuthorizationBoundary(
				static fn (): array => array(
					'classification' => 'failed',
					'cimd_counters'  => array(
						'dns'  => 2,
						'tcp'  => 1,
						'tls'  => 0,
						'http' => 0,
					),
				)
			);
			$dispatcher  = function (): bool {
				$request = new WP_REST_Request( 'GET', self::ROUTE );
				$this->fixtures->authorize( $request, SyntheticBearerFixtures::CASE_VALID_A_DEFAULT );
				$response = $this->server->dispatch( $request );

				return 200 === $response->get_status()
					&& array( 'protected' => true ) === $response->get_data()
					&& 0 === get_current_user_id()
					&& 0 === $this->restBoundary->contexts()->depth();
			};
			$credentials = CredentialPathProbe::forEstablishedAuthorization(
				'https://client.example/metadata',
				$dispatcher
			);

			$failedAuthorization = $cimd->authorize(
				'https://client.example/metadata',
				'https://client.example/callback',
				1000
			);
			$protected           = $credentials->dispatchProtectedRequest();

			self::assertSame( 'validation_failed', $failedAuthorization['classification'] );
			self::assertSame( 'protected_request_completed', $protected['classification'] );
			self::assertSame(
				array(
					'dns'  => 0,
					'tcp'  => 0,
					'tls'  => 0,
					'http' => 0,
				),
				$protected['cimd_counters']
			);
			self::assertFalse( $protected['credential_disturbed'] );
			self::assertGreaterThan( 0, $this->restBoundary->validator()->validationCount() );
		}
	}
}
