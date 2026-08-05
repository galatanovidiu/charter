<?php
/**
 * Slice 0 discovery output-contract tests.
 *
 * @package GalatanOvidiu\Charter
 */

declare(strict_types=1);

namespace GalatanOvidiu\Charter\Tests\Integration\DiscoveryPublication;

use PHPUnit\Framework\TestCase;

/**
 * Proves fixed-schema sanitization before P5 HTTP evidence is emitted.
 *
 * @since 0.1.0
 */
final class OutputContractTest extends TestCase {

	/**
	 * Temporary capture paths.
	 *
	 * @since 0.1.0
	 *
	 * @var list<string>
	 */
	private array $capturePaths = array();

	/**
	 * Temporary directories.
	 *
	 * @since 0.1.0
	 *
	 * @var list<string>
	 */
	private array $temporaryDirectories = array();

	/**
	 * Removes every temporary capture after each test.
	 *
	 * @since 0.1.0
	 */
	protected function tearDown(): void {
		foreach ( $this->capturePaths as $capturePath ) {
			if ( is_file( $capturePath ) ) {
				// phpcs:ignore WordPress.WP.AlternativeFunctions.unlink_unlink -- Deletes only a test-owned temporary capture.
				unlink( $capturePath );
			}
		}

		foreach ( $this->temporaryDirectories as $temporaryDirectory ) {
			if ( is_dir( $temporaryDirectory ) ) {
				// phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_rmdir -- Deletes only an empty test-owned directory.
				rmdir( $temporaryDirectory );
			}
		}

		parent::tearDown();
	}

	/**
	 * Verifies exact successful whitelisted output.
	 *
	 * @since 0.1.0
	 */
	public function testEmitsOnlyFixedSanitizedFields(): void {
		$issuer  = 'https://issuer.charter.test';
		$headers = $this->capture(
			"HTTP/1.1 200 OK\r\n"
			. "Content-Type: application/json; charset=UTF-8\r\n"
			. "Access-Control-Allow-Origin: *\r\n"
			. "Cache-Control: no-store\r\n"
			. "Content-Location: {$issuer}/.well-known/oauth-authorization-server\r\n"
			. "X-Charter-Proof-Front-Controller-Reached: 1\r\n"
			. "X-Charter-Proof-WordPress-Version: 6.9.5\r\n\r\n"
		);
		$body    = $this->capture(
			// phpcs:ignore WordPress.WP.CapitalPDangit.MisspelledInText -- OAuth scope names are case-sensitive wire values.
			'{"issuer":"https://issuer.charter.test","authorization_endpoint":"https://issuer.charter.test/charter-proof/authorize","token_endpoint":"https://issuer.charter.test/charter-proof/token","registration_endpoint":"https://issuer.charter.test/charter-proof/register","revocation_endpoint":"https://issuer.charter.test/charter-proof/revoke","response_types_supported":["code"],"response_modes_supported":["query"],"grant_types_supported":["authorization_code","refresh_token"],"token_endpoint_auth_methods_supported":["none","client_secret_post"],"revocation_endpoint_auth_methods_supported":["none","client_secret_post"],"code_challenge_methods_supported":["S256"],"scopes_supported":["wordpress:access","offline_access"]}'
		);

		$result = $this->validate( $headers, $body );

		self::assertSame( 0, $result['status'] );
		self::assertCount( 1, $result['output'] );
		$record = json_decode( $result['output'][0], true, 512, JSON_THROW_ON_ERROR );

		self::assertSame( 200, $record['status'] );
		self::assertTrue( $record['status_match'] );
		self::assertSame( 'application/json', $record['content_type_class'] );
		self::assertTrue( $record['identity_match'] );
		self::assertTrue( $record['wordpress_tree_version_match'] );
		self::assertTrue( $record['verification_accepted'] );
		self::assertArrayNotHasKey( 'headers', $record );
		self::assertArrayNotHasKey( 'body', $record );
	}

	/**
	 * Verifies that unexpected secret-bearing headers fail before emission.
	 *
	 * @since 0.1.0
	 */
	public function testRejectsSecretLikeHeaderBeforeFixedOutput(): void {
		$headers = $this->capture(
			"HTTP/1.1 200 OK\r\n"
			. "Content-Type: application/json\r\n"
			. "Set-Cookie: proof_session=not-retained\r\n\r\n"
		);
		$body    = $this->capture( '{"issuer":"https://issuer.charter.test"}' );

		$result = $this->validate( $headers, $body );

		self::assertSame( 1, $result['status'] );
		self::assertCount( 1, $result['output'] );
		self::assertSame( 'P5 output validation failed: secret-like material appeared in the capture', $result['output'][0] );
		self::assertStringNotContainsString( 'proof_session', implode( "\n", $result['output'] ) );
	}

	/**
	 * Verifies that matching status and routing cannot hide invalid metadata.
	 *
	 * @since 0.1.0
	 */
	public function testRejectsMetadataThatDoesNotMatchTheExactHttpContract(): void {
		$issuer  = 'https://issuer.charter.test';
		$headers = $this->capture(
			"HTTP/1.1 200 OK\r\n"
			. "Content-Type: application/json; charset=UTF-8\r\n"
			. "Access-Control-Allow-Origin: *\r\n"
			. "Cache-Control: no-store\r\n"
			. "Content-Location: {$issuer}/.well-known/oauth-authorization-server\r\n"
			. "X-Charter-Proof-Front-Controller-Reached: 1\r\n"
			. "X-Charter-Proof-WordPress-Version: 6.9.5\r\n\r\n"
		);
		$body    = $this->capture( '{"issuer":"https://attacker.invalid"}' );

		$result = $this->validate( $headers, $body );

		self::assertSame( 1, $result['status'] );
		self::assertSame(
			'P5 output validation failed: the response did not match the exact HTTP contract',
			$result['output'][0]
		);
	}

	/**
	 * Verifies every accepted metadata response field is an enforced gate.
	 *
	 * @since 0.1.0
	 *
	 * @dataProvider invalidMetadataBoundaryProvider
	 *
	 * @param string $headers Raw HTTP headers.
	 * @param string $body    Raw HTTP body.
	 */
	public function testRejectsInvalidMetadataBoundaryFields( string $headers, string $body ): void {
		$result = $this->validate( $this->capture( $headers ), $this->capture( $body ) );

		self::assertSame( 1, $result['status'] );
		self::assertSame(
			'P5 output validation failed: the response did not match the exact HTTP contract',
			$result['output'][0]
		);
	}

	/**
	 * Verifies synthetic interceptor JSON is observed but never accepted.
	 *
	 * @since 0.1.0
	 */
	public function testRejectsSyntheticJsonBeforeTheWordPressFrontController(): void {
		$headers = $this->capture(
			"HTTP/1.1 200 OK\r\n"
			. "Content-Type: application/json\r\n\r\n"
		);
		$body    = $this->capture( '{"issuer":"https://interceptor.invalid"}' );

		$result = $this->validate( $headers, $body, 'false' );

		self::assertSame( 0, $result['status'] );
		$record = json_decode( $result['output'][0], true, 512, JSON_THROW_ON_ERROR );
		self::assertFalse( $record['front_controller_reached'] );
		self::assertFalse( $record['metadata_match'] );
		self::assertFalse( $record['verification_accepted'] );
	}

	/**
	 * Verifies a negative WordPress lane cannot carry a Charter identity.
	 *
	 * @since 0.1.0
	 */
	public function testRejectsCharterIdentityFromANegativeLane(): void {
		$headers = $this->capture(
			"HTTP/1.1 404 Not Found\r\n"
			. "Content-Type: application/json\r\n"
			. "X-Charter-Proof-Front-Controller-Reached: 1\r\n"
			. "X-Charter-Proof-WordPress-Version: 6.9.5\r\n\r\n"
		);
		$body    = $this->capture( '{"issuer":"https://issuer.charter.test"}' );

		$result = $this->validate( $headers, $body, 'true', 404, '' );

		self::assertSame( 1, $result['status'] );
		self::assertSame(
			'P5 output validation failed: the response did not match the exact HTTP contract',
			$result['output'][0]
		);
	}

	/**
	 * Verifies that only the data-free loopback relay can join the host network.
	 *
	 * @since 0.1.0
	 */
	public function testDockerFixtureUsesOnlyInternalNetworks(): void {
		$composePath = CHARTER_TEST_ROOT . '/tests/fixtures/discovery-publication/docker-compose.yml';
		// phpcs:ignore WordPress.WP.AlternativeFunctions.file_get_contents_file_get_contents -- Reads the checked-in proof fixture.
		$compose = file_get_contents( $composePath );

		self::assertIsString( $compose );
		self::assertStringContainsString( 'host-relay:', $compose );
		self::assertSame( 1, substr_count( $compose, '- host-edge' ) );
		self::assertSame( 2, substr_count( $compose, 'internal: true' ) );
	}

	/**
	 * Verifies the relay can start when the browser proof creates only one lane.
	 *
	 * @since 0.1.0
	 */
	public function testHostRelayAllowsAbsentOptionalBackends(): void {
		$configPath = CHARTER_TEST_ROOT . '/tests/fixtures/discovery-publication/haproxy/host-relay.cfg';
		// phpcs:ignore WordPress.WP.AlternativeFunctions.file_get_contents_file_get_contents -- Reads the checked-in proof fixture.
		$config = file_get_contents( $configPath );

		self::assertIsString( $config );
		self::assertSame( 8, substr_count( $config, 'init-addr libc,none' ) );
		self::assertStringNotContainsString( 'default_backend apache_tls', $config );
	}

	/**
	 * Verifies that ambient version variables cannot move the WordPress proof target.
	 *
	 * @since 0.1.0
	 */
	public function testCiRunnerPinsTheExactWordPressSource(): void {
		$runnerPath = CHARTER_TEST_ROOT . '/tools/run-slice0-discovery-publication-tests.sh';
		// phpcs:ignore WordPress.WP.AlternativeFunctions.file_get_contents_file_get_contents -- Reads the checked-in proof runner.
		$runner = file_get_contents( $runnerPath );

		self::assertIsString( $runner );
		self::assertStringContainsString( 'export WORDPRESS_BRANCH="6.9"', $runner );
		self::assertStringContainsString(
			'export WP_ENV_CORE="https://downloads.w.org/release/wordpress-6.9.5.zip"',
			$runner
		);
		self::assertStringNotContainsString( 'WORDPRESS_BRANCH:-', $runner );
		self::assertStringNotContainsString( 'WP_ENV_CORE:-', $runner );
	}

	/**
	 * Verifies the complete prepared routing boundary in fresh and reused processes.
	 *
	 * @since 0.1.0
	 */
	public function testRunnerRepeatsPreparedBoundaryMatrixInBothProcessModes(): void {
		$runnerPath = CHARTER_TEST_ROOT . '/tools/run-slice0-discovery-publication.sh';
		// phpcs:ignore WordPress.WP.AlternativeFunctions.file_get_contents_file_get_contents -- Reads the checked-in proof runner.
		$runner = file_get_contents( $runnerPath );

		self::assertIsString( $runner );
		self::assertSame( 3, substr_count( $runner, 'run_prepared_boundary_matrix' ) );
		self::assertStringContainsString(
			"run_state_matrix prepared fresh\nrun_prepared_boundary_matrix",
			$runner
		);
		self::assertStringContainsString(
			"run_state_matrix prepared reused\nrun_prepared_boundary_matrix",
			$runner
		);
	}

	/**
	 * Verifies cleanup commands and the manual session have wall-clock bounds.
	 *
	 * @since 0.1.0
	 */
	public function testRunnersBoundCleanupAndManualWaits(): void {
		$runnerPath = CHARTER_TEST_ROOT . '/tools/run-slice0-discovery-publication.sh';
		$outerPath  = CHARTER_TEST_ROOT . '/tools/run-slice0-discovery-publication-tests.sh';
		// phpcs:ignore WordPress.WP.AlternativeFunctions.file_get_contents_file_get_contents -- Reads the checked-in proof runner.
		$runner = file_get_contents( $runnerPath );
		// phpcs:ignore WordPress.WP.AlternativeFunctions.file_get_contents_file_get_contents -- Reads the checked-in proof runner.
		$outer = file_get_contents( $outerPath );

		self::assertIsString( $runner );
		self::assertIsString( $outer );
		self::assertStringContainsString( 'timeout_command="$(command -v gtimeout || command -v timeout || true)"', $runner );
		self::assertStringContainsString( 'timeout_command="$(command -v gtimeout || command -v timeout || true)"', $outer );
		self::assertStringContainsString( '--kill-after=2 10 docker compose', $runner );
		self::assertStringContainsString( '--kill-after=2 20 docker compose', $runner );
		self::assertStringContainsString( '--kill-after=5 30 npm run test:slice0:multisite:destroy', $outer );
		self::assertStringContainsString( 'p5_wp_env_started=false', $outer );
		self::assertStringContainsString( '[[ true == "${p5_wp_env_started}" ]] && ! destroy_wordpress', $outer );
		self::assertStringContainsString( "p5_wp_env_started=true\nnpm run test:slice0:multisite:start", $outer );
		self::assertStringContainsString( 'read -r -t 600 p5_browser_command', $runner );
		self::assertStringContainsString( '"reason_code":"incomplete_cleanup"', $runner );
		self::assertStringContainsString( '"reason_code":"incomplete_cleanup"', $outer );
	}

	/**
	 * Verifies a bounded cleanup failure cannot preserve a successful exit.
	 *
	 * @since 0.1.0
	 */
	public function testCleanupTimeoutProducesFixedFailure(): void {
		$temporaryDirectory = sys_get_temp_dir() . '/charter-p5-timeout-' . bin2hex( random_bytes( 8 ) );
		$fakeTimeout        = $temporaryDirectory . '/gtimeout';

		// phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_mkdir -- Creates only a test-owned temporary directory.
		self::assertTrue( mkdir( $temporaryDirectory, 0700 ) );
		$this->temporaryDirectories[] = $temporaryDirectory;
		// phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_file_put_contents -- Writes a test-owned fake executable.
		self::assertNotFalse( file_put_contents( $fakeTimeout, "#!/usr/bin/env bash\nexit 124\n" ) );
		$this->capturePaths[] = $fakeTimeout;
		// phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_chmod -- Makes only a test-owned fake executable runnable.
		self::assertTrue( chmod( $fakeTimeout, 0700 ) );

		$path = getenv( 'PATH' );
		self::assertIsString( $path );
		$runner  = CHARTER_TEST_ROOT . '/tools/run-slice0-discovery-publication.sh';
		$command = 'PATH=' . escapeshellarg( $temporaryDirectory . ':' . $path )
			. ' bash ' . escapeshellarg( $runner ) . ' --unknown 2>&1';
		$output  = array();
		$status  = 0;

		exec( $command, $output, $status ); // phpcs:ignore WordPress.PHP.DiscouragedPHPFunctions.system_calls_exec -- Runs the bounded proof cleanup failure probe.

		self::assertSame( 70, $status );
		self::assertContains( '{"status":"failed","phase":"cleanup","reason_code":"incomplete_cleanup"}', $output );
	}

	/**
	 * Supplies metadata responses that match status/routing but violate one exact boundary.
	 *
	 * @since 0.1.0
	 *
	 * @return array<string, array{string, string}> Invalid responses.
	 */
	public function invalidMetadataBoundaryProvider(): array {
		$issuer = 'https://issuer.charter.test';
		// phpcs:ignore WordPress.WP.CapitalPDangit.MisspelledInText -- OAuth scope names are case-sensitive wire values.
		$body = '{"issuer":"https://issuer.charter.test","authorization_endpoint":"https://issuer.charter.test/charter-proof/authorize","token_endpoint":"https://issuer.charter.test/charter-proof/token","registration_endpoint":"https://issuer.charter.test/charter-proof/register","revocation_endpoint":"https://issuer.charter.test/charter-proof/revoke","response_types_supported":["code"],"response_modes_supported":["query"],"grant_types_supported":["authorization_code","refresh_token"],"token_endpoint_auth_methods_supported":["none","client_secret_post"],"revocation_endpoint_auth_methods_supported":["none","client_secret_post"],"code_challenge_methods_supported":["S256"],"scopes_supported":["wordpress:access","offline_access"]}';
		$base = "HTTP/1.1 200 OK\r\n"
			. "Content-Type: application/json; charset=UTF-8\r\n"
			. "Access-Control-Allow-Origin: *\r\n"
			. "Cache-Control: no-store\r\n"
			. "Content-Location: {$issuer}/.well-known/oauth-authorization-server\r\n"
			. "X-Charter-Proof-Front-Controller-Reached: 1\r\n"
			. "X-Charter-Proof-WordPress-Version: 6.9.5\r\n\r\n";

		return array(
			'duplicate content type'  => array( str_replace( "Content-Type: application/json; charset=UTF-8\r\n", "Content-Type: text/html\r\nContent-Type: application/json; charset=UTF-8\r\n", $base ), $body ),
			'duplicate cache control' => array( str_replace( "Cache-Control: no-store\r\n", "Cache-Control: public\r\nCache-Control: no-store\r\n", $base ), $body ),
			'invalid JSON media type' => array( str_replace( 'application/json; charset=UTF-8', 'application/jsonp', $base ), $body ),
			'missing cors'            => array( str_replace( "Access-Control-Allow-Origin: *\r\n", '', $base ), $body ),
			'credentialed cors'       => array( str_replace( 'Cache-Control', "Access-Control-Allow-Credentials: true\r\nCache-Control", $base ), $body ),
			'missing no-store'        => array( str_replace( "Cache-Control: no-store\r\n", '', $base ), $body ),
			'wrong content location'  => array( str_replace( 'oauth-authorization-server', 'wrong-location', $base ), $body ),
			'backend disclosure'      => array( str_replace( "\r\n\r\n", "\r\nX-Upstream: proxy-origin\r\n\r\n", $base ), $body ),
			'extra metadata member'   => array( $base, substr( $body, 0, -1 ) . ',"unexpected":true}' ),
		);
	}

	/**
	 * Writes one bounded temporary capture.
	 *
	 * @since 0.1.0
	 *
	 * @param string $contents The capture contents.
	 * @return string The capture path.
	 */
	private function capture( string $contents ): string {
		$path = tempnam( sys_get_temp_dir(), 'charter-p5-output-' );

		self::assertIsString( $path );
		// phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_file_put_contents -- Writes only a test-owned temporary capture.
		self::assertNotFalse( file_put_contents( $path, $contents ) );
		$this->capturePaths[] = $path;

		return $path;
	}

	/**
	 * Runs the standalone output validator against private captures.
	 *
	 * @since 0.1.0
	 *
	 * @param string      $headersPath     The header capture path.
	 * @param string      $bodyPath        The body capture path.
	 * @param string      $expectedReached Whether the WordPress proof front controller must be reached.
	 * @param int         $expectedStatus  The exact expected HTTP status.
	 * @param string|null $expectedIdentity The exact expected identity, or null for the default issuer.
	 * @return array{status: int, output: list<string>} The command result.
	 */
	private function validate(
		string $headersPath,
		string $bodyPath,
		string $expectedReached = 'true',
		int $expectedStatus = 200,
		?string $expectedIdentity = null
	): array {
		$issuer = 'https://issuer.charter.test';
		$tool   = CHARTER_TEST_ROOT . '/tools/validate-slice0-discovery-publication-output.php';

		if ( null === $expectedIdentity ) {
			$expectedIdentity = $issuer;
		}

		$command = implode(
			' ',
			array(
				escapeshellarg( PHP_BINARY ),
				escapeshellarg( $tool ),
				'--lane=unit',
				'--state=prepared',
				'--process-mode=fresh',
				'--url=' . escapeshellarg( $issuer . '/.well-known/oauth-authorization-server' ),
				'--expected-status=' . $expectedStatus,
				'--expected-identity=' . escapeshellarg( $expectedIdentity ),
				'--expected-reached=' . escapeshellarg( $expectedReached ),
				'--headers=' . escapeshellarg( $headersPath ),
				'--body=' . escapeshellarg( $bodyPath ),
				'2>&1',
			)
		);
		$output  = array();
		$status  = 0;

		exec( $command, $output, $status ); // phpcs:ignore WordPress.PHP.DiscouragedPHPFunctions.system_calls_exec -- Runs the bounded standalone proof validator.

		return array(
			'status' => $status,
			'output' => $output,
		);
	}
}
