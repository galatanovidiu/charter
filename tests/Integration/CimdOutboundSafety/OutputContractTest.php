<?php
/**
 * Slice 0 CIMD outbound-safety output contract tests.
 *
 * @package GalatanOvidiu\Charter
 */

declare(strict_types=1);

namespace GalatanOvidiu\Charter\Tests\Integration\CimdOutboundSafety;

use PHPUnit\Framework\TestCase;

/**
 * Proves only fixed records and confined Compose topology reach P3 evidence.
 *
 * @since 0.1.0
 */
final class OutputContractTest extends TestCase {

	/**
	 * Test-owned temporary input files.
	 *
	 * @var list<string>
	 */
	private array $paths = array();

	/**
	 * Removes every test-owned input capture.
	 */
	protected function tearDown(): void {
		foreach ( $this->paths as $path ) {
			if ( is_file( $path ) ) {
				// phpcs:ignore WordPress.WP.AlternativeFunctions.unlink_unlink -- Deletes only a test-owned temporary input.
				unlink( $path );
			}
		}

		parent::tearDown();
	}

	/**
	 * Verifies the validator accepts and preserves only the exact field set.
	 */
	public function testAcceptsOneExactFixedEvidenceRecord(): void {
		$result = $this->validateRecord( self::baseRecord() );

		self::assertSame( 0, $result['status'] );
		self::assertCount( 1, $result['output'] );
		$record = json_decode( $result['output'][0], true, 32, JSON_THROW_ON_ERROR );
		self::assertSame( array_keys( self::baseRecord() ), array_keys( $record ) );
		self::assertSame( 'p3-output-contract', $record['case_id'] );
		self::assertArrayNotHasKey( 'headers', $record );
		self::assertArrayNotHasKey( 'body', $record );
		self::assertArrayNotHasKey( 'environment', $record );
	}

	/**
	 * Verifies an extra capture-shaped member fails before any record emission.
	 */
	public function testRejectsAnyFieldOutsideTheFixedEvidenceSchema(): void {
		$record            = self::baseRecord();
		$record['headers'] = array();
		$result            = $this->validateRecord( $record );

		self::assertSame( 1, $result['status'] );
		self::assertSame(
			array( 'P3 output validation failed: fixed schema rejected.' ),
			$result['output']
		);
	}

	/**
	 * Verifies the Compose validator accepts only the fixed internal topology.
	 */
	public function testAcceptsTheExactConfinedComposeProjection(): void {
		$result = $this->validateCompose( self::composeProjection() );

		self::assertSame( 0, $result['status'] );
		self::assertCount( 1, $result['output'] );
		$record = json_decode( $result['output'][0], true, 32, JSON_THROW_ON_ERROR );
		self::assertSame( 'compose-static', $record['case_id'] );
		self::assertSame( 'preflight', $record['phase'] );
		self::assertSame( 'static', $record['runtime_classification'] );
	}

	/**
	 * Verifies any published port makes the Compose topology invalid.
	 */
	public function testRejectsAComposeProjectionWithAPublishedPort(): void {
		$compose                                = self::composeProjection();
		$compose['services']['origin']['ports'] = array( '443:443' );
		$result                                 = $this->validateCompose( $compose );

		self::assertSame( 1, $result['status'] );
		self::assertSame(
			array( 'P3 output validation failed: fixed schema rejected.' ),
			$result['output']
		);
	}

	/**
	 * Verifies the checked-in fixture exposes only fixed control inputs.
	 */
	public function testComposeSourcePinsTheFixedFixtureEnvironment(): void {
		$path = CHARTER_TEST_ROOT . '/tests/fixtures/cimd-outbound-safety/docker-compose.yml';
		// phpcs:ignore WordPress.WP.AlternativeFunctions.file_get_contents_file_get_contents -- Reads the checked-in proof fixture.
		$compose = file_get_contents( $path );

		self::assertIsString( $compose );
		self::assertSame( 1, substr_count( $compose, 'internal: true' ) );
		self::assertSame( 1, substr_count( $compose, 'enable_ipv6: true' ) );
		self::assertSame( 2, substr_count( $compose, 'P3_FIXTURE_CA_FILE:' ) );
		self::assertSame( 2, substr_count( $compose, 'P3_FIXTURE_CLIENT_ID:' ) );
		self::assertSame( 2, substr_count( $compose, 'P3_FIXTURE_CONTROL_URL:' ) );
		self::assertSame( 2, substr_count( $compose, 'P3_FIXTURE_DNS_SERVER:' ) );
		self::assertSame( 2, substr_count( $compose, 'P3_FIXTURE_PROXY_URL:' ) );
		self::assertSame( 2, substr_count( $compose, 'P3_FIXTURE_SOCKS_PROXY_URL:' ) );
		self::assertStringNotContainsString( 'ports:', $compose );
		self::assertStringNotContainsString( 'network_mode:', $compose );
		self::assertStringNotContainsString( 'extra_hosts:', $compose );
	}

	/**
	 * Runs the standalone validator against one encoded record.
	 *
	 * @param array<string, mixed> $record Candidate record.
	 * @return array{status: int, output: list<string>} Process result.
	 */
	private function validateRecord( array $record ): array {
		// phpcs:ignore WordPress.WP.AlternativeFunctions.json_encode_json_encode -- WordPress is intentionally absent from this standalone validator input.
		$encoded = json_encode( $record, JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR ) . "\n";
		$path    = $this->capture( $encoded );
		return $this->runValidator( '< ' . escapeshellarg( $path ) );
	}

	/**
	 * Runs the standalone validator against one Compose JSON projection.
	 *
	 * @param array<string, mixed> $compose Candidate Compose projection.
	 * @return array{status: int, output: list<string>} Process result.
	 */
	private function validateCompose( array $compose ): array {
		// phpcs:ignore WordPress.WP.AlternativeFunctions.json_encode_json_encode -- WordPress is intentionally absent from this standalone validator input.
		$encoded = json_encode( $compose, JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR );
		$path    = $this->capture( $encoded );
		return $this->runValidator( '--compose-config ' . escapeshellarg( $path ) );
	}

	/**
	 * Executes the bounded standalone P3 validator.
	 *
	 * @param string $arguments Shell-safe validator arguments.
	 * @return array{status: int, output: list<string>} Process result.
	 */
	private function runValidator( string $arguments ): array {
		$validator = CHARTER_TEST_ROOT . '/tools/validate-slice0-cimd-outbound-safety-output.php';
		$command   = escapeshellarg( PHP_BINARY ) . ' ' . escapeshellarg( $validator ) . ' ' . $arguments . ' 2>&1';
		$output    = array();
		$status    = 0;

		exec( $command, $output, $status ); // phpcs:ignore WordPress.PHP.DiscouragedPHPFunctions.system_calls_exec -- Runs only the bounded standalone proof validator.

		return array(
			'status' => $status,
			'output' => $output,
		);
	}

	/**
	 * Writes one test-owned bounded validator input.
	 *
	 * @param string $contents Fixed input contents.
	 */
	private function capture( string $contents ): string {
		$path = tempnam( sys_get_temp_dir(), 'charter-p3-output-' );
		self::assertIsString( $path );
		// phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_file_put_contents -- Writes only a test-owned temporary validator input.
		self::assertNotFalse( file_put_contents( $path, $contents ) );
		$this->paths[] = $path;
		return $path;
	}

	/**
	 * Returns one exact fixed evidence record.
	 *
	 * @return array<string, mixed> Evidence record.
	 */
	private static function baseRecord(): array {
		return array(
			'status'                 => 'passed',
			'phase'                  => 'pure',
			'case_id'                => 'p3-output-contract',
			'runtime_classification' => 'pure-php',
			'url_classification'     => 'accepted',
			'dns_classification'     => 'bounded',
			'address_classification' => 'screened',
			'media_classification'   => 'accepted-json',
			'cache_classification'   => 'fresh',
			'error_classification'   => 'none',
			'status_code'            => 200,
			'body_bytes'             => 1,
			'elapsed_ms'             => 1,
			'counters'               => array(
				'dns_query'       => 1,
				'tcp_connection'  => 1,
				'tls_handshake'   => 1,
				'http_request'    => 1,
				'redirect_target' => 0,
				'embedded_url'    => 0,
				'proxy'           => 0,
				'credential_path' => 0,
			),
			'flags'                  => array(
				'tls_hostname_verified'  => true,
				'screened_peer_matched'  => true,
				'redirect_followed'      => false,
				'snapshot_authoritative' => true,
				'stale_fallback_used'    => false,
				'consent_reusable'       => false,
				'credential_disturbed'   => false,
			),
			'document_fingerprint'   => str_repeat( 'a', 64 ),
			'redirect_fingerprint'   => str_repeat( 'b', 64 ),
			'cleanup'                => array(
				'processes_remaining'    => 0,
				'containers_remaining'   => 0,
				'networks_remaining'     => 0,
				'temp_files_remaining'   => 0,
				'private_keys_remaining' => 0,
				'hooks_remaining'        => 0,
				'listeners_remaining'    => 0,
			),
		);
	}

	/**
	 * Returns the exact valid Compose shape consumed by the output validator.
	 *
	 * @return array<string, mixed> Compose projection.
	 */
	private static function composeProjection(): array {
		$service  = array(
			'image'        => 'proof@example.invalid@sha256:' . str_repeat( 'a', 64 ),
			'read_only'    => true,
			'cap_drop'     => array( 'ALL' ),
			'security_opt' => array( 'no-new-privileges:true' ),
			'networks'     => array( 'hostile' => null ),
		);
		$services = array();
		foreach (
			array(
				'control',
				'dns',
				'embedded-url-sink',
				'http-proxy',
				'origin',
				'origin6',
				'redirect-sink',
				'socks-proxy',
				'special-sink',
				'wp84',
				'wp85',
			) as $name
		) {
			$services[ $name ] = $service;
		}

		return array(
			'services' => $services,
			'networks' => array(
				'hostile' => array(
					'internal'    => true,
					'enable_ipv6' => true,
				),
			),
		);
	}
}
