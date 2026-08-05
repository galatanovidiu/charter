<?php
/**
 * Disposable Slice 0 unsupported-topology diagnostics.
 *
 * @package GalatanOvidiu\Charter
 */

declare(strict_types=1);

namespace GalatanOvidiu\Charter\Tests\Prototype\DiscoveryPublication;

use GalatanOvidiu\Charter\Tests\Prototype\Multisite\IssuerIdentity;
use GalatanOvidiu\Charter\Tests\Prototype\Multisite\SiteIssuerLifecycle;

/**
 * Projects equivalent non-secret diagnostics for a path-bearing site issuer.
 *
 * @since 0.1.0
 */
final class UnsupportedTopologyDiagnostics {

	/**
	 * Registers disposable WordPress diagnostic surfaces.
	 *
	 * @since 0.1.0
	 */
	public static function register(): void {
		if ( false === has_action( 'admin_notices', array( self::class, 'renderAdministratorNotice' ) ) ) {
			add_action( 'admin_notices', array( self::class, 'renderAdministratorNotice' ) );
		}

		if ( false === has_filter( 'site_status_tests', array( self::class, 'addSiteHealthTest' ) ) ) {
			add_filter( 'site_status_tests', array( self::class, 'addSiteHealthTest' ) );
		}

		if ( defined( 'WP_CLI' ) && WP_CLI && class_exists( '\\WP_CLI' ) ) {
			\WP_CLI::add_command( 'charter-slice0 topology', array( self::class, 'runWpCliCommand' ) );
		}
	}

	/**
	 * Renders the persistent current-site administrator notice.
	 *
	 * @since 0.1.0
	 */
	public static function renderAdministratorNotice(): void {
		$diagnostics = self::forCurrentSite();

		if ( true === $diagnostics['supported'] ) {
			return;
		}

		echo $diagnostics['administrator_notice']; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- Escaped during fixed diagnostic construction.
	}

	/**
	 * Registers the critical current-site Site Health test.
	 *
	 * @since 0.1.0
	 *
	 * @param array<string, array<string, array<string, mixed>>> $tests Registered tests.
	 * @return array<string, array<string, array<string, mixed>>> Registered tests.
	 */
	public static function addSiteHealthTest( array $tests ): array {
		$diagnostics = self::forCurrentSite();

		if ( true === $diagnostics['supported'] ) {
			return $tests;
		}

		$tests['direct']['charter_unsupported_path_topology'] = array(
			'label' => $diagnostics['site_health']['label'],
			'test'  => array( self::class, 'siteHealthResult' ),
		);

		return $tests;
	}

	/**
	 * Returns the exact critical Site Health result.
	 *
	 * @since 0.1.0
	 *
	 * @return array{status: string, label: string, description: string, test: string} Site Health result.
	 */
	public static function siteHealthResult(): array {
		$diagnostics = self::forCurrentSite();

		return array(
			'status'      => (string) ( $diagnostics['site_health']['status'] ?? 'critical' ),
			'label'       => (string) ( $diagnostics['site_health']['label'] ?? 'Charter OAuth topology is unsupported' ),
			'description' => $diagnostics['message'],
			'test'        => 'charter_unsupported_path_topology',
		);
	}

	/**
	 * Emits the same reason through the proof-owned WP-CLI command.
	 *
	 * @since 0.1.0
	 *
	 * @param array                $arguments   Positional arguments.
	 * @param array<string, mixed> $associative Associative arguments.
	 */
	public static function runWpCliCommand( array $arguments, array $associative ): void {
		unset( $arguments );

		$canonicalBase = is_string( $associative['canonical-base'] ?? null )
			? $associative['canonical-base']
			: '';
		$diagnostics   = self::forCanonicalBase( $canonicalBase );

		if ( true === $diagnostics['supported'] ) {
			\WP_CLI::success( 'Charter OAuth topology is supported.' );
			return;
		}

		\WP_CLI::error( $diagnostics['message'] );
	}

	/**
	 * Returns exact proof diagnostics for one canonical public OAuth base.
	 *
	 * @since 0.1.0
	 *
	 * @param string $canonicalBase The detected canonical public OAuth base.
	 * @return array{
	 *     supported: bool,
	 *     plugin_active: bool,
	 *     fatal: bool,
	 *     reason_code: string|null,
	 *     message: string,
	 *     administrator_notice: string,
	 *     site_health: array<string, string>,
	 *     wp_cli: array{message: string, exit_code: int}|array{}
	 * } The proof diagnostics.
	 */
	public static function forCanonicalBase( string $canonicalBase ): array {
		// phpcs:ignore WordPress.WP.AlternativeFunctions.parse_url_parse_url -- This pure proof class also runs outside WordPress.
		$parts = parse_url( $canonicalBase );
		$path  = is_array( $parts ) && is_string( $parts['path'] ?? null ) ? $parts['path'] : '';

		if ( '' === $path ) {
			return array(
				'supported'            => true,
				'plugin_active'        => true,
				'fatal'                => false,
				'reason_code'          => null,
				'message'              => '',
				'administrator_notice' => '',
				'site_health'          => array(),
				'wp_cli'               => array(),
			);
		}

		$message = 'Charter cannot enable OAuth for Canonical public OAuth base URL '
			. $canonicalBase
			. '; v1 requires a bare origin without a path.';

		return array(
			'supported'            => false,
			'plugin_active'        => true,
			'fatal'                => false,
			'reason_code'          => 'unsupported_path_topology',
			'message'              => $message,
			'administrator_notice' => '<div class="notice notice-error"><p>' . htmlspecialchars( $message, ENT_QUOTES ) . '</p></div>',
			'site_health'          => array(
				'status'      => 'critical',
				'label'       => 'Charter OAuth topology is unsupported',
				'description' => $message,
			),
			'wp_cli'               => array(
				'message'   => $message,
				'exit_code' => 1,
			),
		);
	}

	/**
	 * Returns diagnostics for the exact identity already selected by WordPress.
	 *
	 * @since 0.1.0
	 *
	 * @return array{
	 *     supported: bool,
	 *     plugin_active: bool,
	 *     fatal: bool,
	 *     reason_code: string|null,
	 *     message: string,
	 *     administrator_notice: string,
	 *     site_health: array<string, string>,
	 *     wp_cli: array{message: string, exit_code: int}|array{}
	 * } The proof diagnostics.
	 */
	private static function forCurrentSite(): array {
		$identity = SiteIssuerLifecycle::identityForCurrentSite();

		if ( ! $identity instanceof IssuerIdentity ) {
			return self::forCanonicalBase( '' );
		}

		return self::forCanonicalBase( $identity->issuer() );
	}
}
