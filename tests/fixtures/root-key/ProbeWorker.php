<?php
/**
 * Fresh-process worker for the disposable Slice 0 root-key probes.
 *
 * @package GalatanOvidiu\Charter
 */

declare(strict_types=1);

namespace GalatanOvidiu\Charter\Tests\Fixtures\RootKey;

use GalatanOvidiu\Charter\Tests\Prototype\Multisite\DigestedProofCredentialStore;
use GalatanOvidiu\Charter\Tests\Prototype\Multisite\EffectiveRootKeySource;
use GalatanOvidiu\Charter\Tests\Prototype\Multisite\ExplicitKeyGuard;
use GalatanOvidiu\Charter\Tests\Prototype\Multisite\IssuerIdentity;
use GalatanOvidiu\Charter\Tests\Prototype\Multisite\SiteIssuerLifecycle;
use RuntimeException;
use Throwable;

require_once __DIR__ . '/ProbeContract.php';

/**
 * Runs one isolated probe phase without exposing secret material.
 */
final class ProbeWorker {

	/**
	 * Effective WordPress salt schemes in D27 order.
	 *
	 * @var list<string>
	 */
	private const SCHEMES = array( 'auth', 'secure_auth', 'logged_in', 'nonce' );

	/**
	 * Network options used by WordPress's fallback path.
	 *
	 * @var list<string>
	 */
	private const FALLBACK_OPTIONS = array(
		'auth_key',
		'auth_salt',
		'secure_auth_key',
		'secure_auth_salt',
		'logged_in_key',
		'logged_in_salt',
		'nonce_key',
		'nonce_salt',
	);

	/**
	 * Runs the requested phase.
	 *
	 * @param string $phase      Probe phase.
	 * @param string $state_file Private temporary comparison-state path.
	 * @return array<string, bool>
	 * @throws RuntimeException When the requested phase is unknown.
	 */
	public static function run( string $phase, string $state_file ): array {
		return match ( $phase ) {
			'reset'          => self::resetFallbackOptions(),
			'initial'        => self::runInitialFallbackProbe( $state_file ),
			'sibling-first'  => self::runSiblingFallbackProbe( $state_file, 0 ),
			'sibling-second' => self::runSiblingFallbackProbe( $state_file, 1 ),
			'reuse'          => self::runReuseFallbackProbe( $state_file ),
			'explicit'       => self::runExplicitOverrideProbe(),
			'failure'        => self::runExpectedFailureProbe(),
			'cleanup'        => self::cleanup( $state_file ),
			default    => throw new RuntimeException( 'Unknown probe phase.' ),
		};
	}

	/**
	 * Removes any prior disposable fallback values in a separate process.
	 *
	 * @return array<string, bool>
	 */
	private static function resetFallbackOptions(): array {
		self::loadWordPress( true );
		$network_id = get_current_network_id();

		foreach ( self::FALLBACK_OPTIONS as $option ) {
			delete_network_option( $network_id, $option );
		}

		return array(
			'fallback_options_absent' => self::fallbackOptionsAbsent( $network_id ),
		);
	}

	/**
	 * Generates fallback values and creates sibling contexts for fresh workers.
	 *
	 * @param string $state_file Private temporary comparison-state path.
	 * @return array<string, bool>
	 */
	private static function runInitialFallbackProbe( string $state_file ): array {
		self::loadWordPress( true );
		$network_id = get_current_network_id();
		$effective  = self::effectiveValues();
		$options    = self::fallbackOptionValues( $network_id );
		$site_ids   = self::createSiblingSites();

		self::writeState(
			$state_file,
			array(
				'effective_tag' => self::comparisonTag( $effective ),
				'options_tag'   => self::comparisonTag( $options ),
				'site_ids'      => $site_ids,
				'site_requests' => self::requestContextsForSites( $site_ids ),
			)
		);

		return array(
			'sample_constants_forced_fallback'      => self::effectiveValuesMatchOptions( $effective, $options ),
			'all_four_schemes_used_network_options' => 8 === count( $options ),
		);
	}

	/**
	 * Proves one sibling observes the network fallback from bootstrap onward.
	 *
	 * Each sibling request context is selected before WordPress loads in its own
	 * process, so any bootstrap-time salt cache is established for that sibling.
	 *
	 * @param string $state_file Private temporary comparison-state path.
	 * @param int    $site_index Sibling index in saved state.
	 * @return array<string, bool>
	 */
	private static function runSiblingFallbackProbe( string $state_file, int $site_index ): array {
		$state         = self::readState( $state_file );
		$site_ids      = $state['site_ids'] ?? null;
		$site_requests = $state['site_requests'] ?? null;
		$site_id       = is_array( $site_ids ) ? ( $site_ids[ $site_index ] ?? null ) : null;
		$site_request  = is_array( $site_requests ) ? ( $site_requests[ $site_index ] ?? null ) : null;

		if (
			! is_int( $site_id )
			|| ! is_array( $site_request )
			|| ! is_string( $site_request['domain'] ?? null )
			|| ! is_string( $site_request['path'] ?? null )
		) {
			return array( 'selected_sibling_read_network_fallback' => false );
		}

		$_SERVER['HTTP_HOST']      = $site_request['domain'];
		$_SERVER['SERVER_NAME']    = $site_request['domain'];
		$_SERVER['REQUEST_URI']    = $site_request['path'];
		$_SERVER['REQUEST_METHOD'] = 'GET';
		$_SERVER['SCRIPT_NAME']    = '/index.php';
		$_SERVER['PHP_SELF']       = '/index.php';

		self::loadWordPress( true );
		$network_id = get_current_network_id();
		$effective  = self::effectiveValues();
		$options    = self::fallbackOptionValues( $network_id );

		return array(
			'selected_sibling_read_network_fallback' => get_current_blog_id() === $site_id
				&& self::effectiveValuesMatchOptions( $effective, $options )
				&& is_string( $state['effective_tag'] ?? null )
				&& hash_equals( $state['effective_tag'], self::comparisonTag( $effective ) ),
		);
	}

	/**
	 * Proves that a second process reads the persisted fallback values.
	 *
	 * @param string $state_file Private temporary comparison-state path.
	 * @return array<string, bool>
	 */
	private static function runReuseFallbackProbe( string $state_file ): array {
		self::loadWordPress( true );
		$state      = self::readState( $state_file );
		$network_id = get_current_network_id();
		$options    = self::fallbackOptionValues( $network_id );
		$effective  = self::effectiveValues();

		return array(
			'second_fresh_process_reused_persisted_values' =>
				is_string( $state['effective_tag'] ?? null )
				&& is_string( $state['options_tag'] ?? null )
				&& hash_equals( $state['effective_tag'], self::comparisonTag( $effective ) )
				&& hash_equals( $state['options_tag'], self::comparisonTag( $options ) )
				&& self::effectiveValuesMatchOptions( $effective, $options ),
		);
	}

	/**
	 * Proves explicit-key precedence across an observable salt-filter change.
	 *
	 * @return array<string, bool>
	 */
	private static function runExplicitOverrideProbe(): array {
		define( 'CHARTER_SECRET_KEY', bin2hex( random_bytes( 48 ) ) );
		require_once dirname( __DIR__, 3 ) . '/vendor/autoload.php';

		$wordpress_not_loaded = ! function_exists( 'wp_salt' );
		$before               = EffectiveRootKeySource::fromConfiguration();

		self::loadWordPress( false );
		DigestedProofCredentialStore::resetProof();
		ExplicitKeyGuard::resetProof();
		SiteIssuerLifecycle::resetProof();

		$saltFilter = static fn( string $salt, string $scheme ): string => $salt . '|charter-slice0-filter-change|' . $scheme;

		try {
			$identity = IssuerIdentity::forCurrentSite();
			SiteIssuerLifecycle::prepare( $identity );
			$enabled          = SiteIssuerLifecycle::recordVerification( $identity->issuer() )
				&& SiteIssuerLifecycle::enable( $identity->issuer() );
			$established      = ExplicitKeyGuard::establish( $before );
			$credential       = bin2hex( random_bytes( 48 ) );
			$issued           = DigestedProofCredentialStore::issue(
				$credential,
				$before,
				$identity,
				$identity->issuer(),
				'access'
			);
			$wordpress_before = self::effectiveValues();

			add_filter( 'salt', $saltFilter, 10, 2 );
			$wordpress_after = self::effectiveValues();
			$after           = EffectiveRootKeySource::fromConfiguration();
			$accepted        = DigestedProofCredentialStore::accepts(
				$credential,
				$after,
				$identity,
				$identity->issuer(),
				'access'
			);

			return array(
				'selected_before_wordpress_load'           => $wordpress_not_loaded && $before->usesExplicitSnapshot(),
				'stable_after_salt_filter_change'          => $wordpress_before !== $wordpress_after
					&& $after->usesExplicitSnapshot()
					&& $before->sameRootAs( $after ),
				'explicit_credential_survived_salt_change' => $enabled && $established && $issued && $accepted,
			);
		} finally {
			remove_filter( 'salt', $saltFilter, 10 );
			DigestedProofCredentialStore::resetProof();
			ExplicitKeyGuard::resetProof();
			SiteIssuerLifecycle::resetProof();
		}
	}

	/**
	 * Throws a marker-bearing failure that the public worker contract suppresses.
	 *
	 * @throws RuntimeException Always, with known non-secret proof markers.
	 */
	private static function runExpectedFailureProbe(): never {
		// phpcs:ignore WordPress.Security.EscapeOutput.ExceptionNotEscaped -- The outer worker contract intentionally suppresses this marker-bearing exception.
		throw new RuntimeException( implode( '|', ProbeContract::FAILURE_OUTPUT_MARKERS ) );
	}

	/**
	 * Removes sites and fallback values created by the disposable probe.
	 *
	 * @param string $state_file Private temporary comparison-state path.
	 * @return array<string, bool>
	 */
	private static function cleanup( string $state_file ): array {
		self::loadWordPress( true );
		$state    = self::readState( $state_file );
		$site_ids = $state['site_ids'] ?? null;

		if ( is_array( $site_ids ) ) {
			foreach ( $site_ids as $site_id ) {
				if ( is_int( $site_id ) && 1 < $site_id && get_site( $site_id ) ) {
					wp_delete_site( $site_id );
				}
			}
		}

		$network_id = get_current_network_id();
		foreach ( self::FALLBACK_OPTIONS as $option ) {
			delete_network_option( $network_id, $option );
		}

		return array(
			'cleanup_complete' => self::fallbackOptionsAbsent( $network_id ),
		);
	}

	/**
	 * Loads the real disposable WordPress installation.
	 *
	 * @param bool $force_fallback Whether to replace configured constants with Core's public sample placeholder.
	 * @throws RuntimeException When WordPress cannot be loaded as Multisite.
	 */
	private static function loadWordPress( bool $force_fallback ): void {
		if ( $force_fallback ) {
			foreach ( array( 'AUTH', 'SECURE_AUTH', 'LOGGED_IN', 'NONCE' ) as $scheme ) {
				// phpcs:ignore WordPress.NamingConventions.PrefixAllGlobals.VariableConstantNameFound -- Intentionally overrides WordPress test constants before bootstrap.
				define( $scheme . '_KEY', 'put your unique phrase here' );
				// phpcs:ignore WordPress.NamingConventions.PrefixAllGlobals.VariableConstantNameFound -- Intentionally overrides WordPress test constants before bootstrap.
				define( $scheme . '_SALT', 'put your unique phrase here' );
			}
		}

		$wordpress_load = '/var/www/html/wp-load.php';

		if ( ! is_file( $wordpress_load ) ) {
			throw new RuntimeException( 'The disposable WordPress bootstrap is unavailable.' );
		}

		self::requireWordPress( $wordpress_load );

		if ( ! is_multisite() ) {
			throw new RuntimeException( 'The probe requires Multisite.' );
		}
	}

	/**
	 * Requires a validated disposable WordPress bootstrap path.
	 *
	 * @param string $wordpress_load Validated WordPress bootstrap path.
	 */
	private static function requireWordPress( string $wordpress_load ): void {
		require_once $wordpress_load;
	}

	/**
	 * Returns the four effective values only to in-process comparisons.
	 *
	 * @return array<string, string>
	 */
	private static function effectiveValues(): array {
		$values = array();
		foreach ( self::SCHEMES as $scheme ) {
			$values[ $scheme ] = wp_salt( $scheme );
		}

		return $values;
	}

	/**
	 * Reads all generated fallback values without returning them from the worker.
	 *
	 * @param int $network_id Network ID.
	 * @return array<string, string>
	 * @throws RuntimeException When a required fallback option is unavailable.
	 */
	private static function fallbackOptionValues( int $network_id ): array {
		$values = array();
		foreach ( self::FALLBACK_OPTIONS as $option ) {
			$value = get_network_option( $network_id, $option, null );
			if ( ! is_string( $value ) || '' === $value ) {
				throw new RuntimeException( 'A fallback option is unavailable.' );
			}
			$values[ $option ] = $value;
		}

		return $values;
	}

	/**
	 * Checks that each effective value came from its two fallback options.
	 *
	 * @param array<string, string> $effective Effective values.
	 * @param array<string, string> $options   Fallback option values.
	 */
	private static function effectiveValuesMatchOptions( array $effective, array $options ): bool {
		foreach ( self::SCHEMES as $scheme ) {
			if ( ! isset( $effective[ $scheme ], $options[ $scheme . '_key' ], $options[ $scheme . '_salt' ] ) ) {
				return false;
			}
			if ( $effective[ $scheme ] !== $options[ $scheme . '_key' ] . $options[ $scheme . '_salt' ] ) {
				return false;
			}
		}

		return true;
	}

	/**
	 * Checks that no fallback option exists.
	 *
	 * @param int $network_id Network ID.
	 */
	private static function fallbackOptionsAbsent( int $network_id ): bool {
		foreach ( self::FALLBACK_OPTIONS as $option ) {
			if ( null !== get_network_option( $network_id, $option, null ) ) {
				return false;
			}
		}

		return true;
	}

	/**
	 * Creates two temporary sibling sites in the current network.
	 *
	 * @return array{0: int, 1: int}
	 * @throws RuntimeException When the current network or a sibling site is unavailable.
	 */
	private static function createSiblingSites(): array {
		$network = get_network();
		if ( null === $network ) {
			throw new RuntimeException( 'The current network is unavailable.' );
		}

		$site_ids = array();
		foreach ( array( 'a', 'b' ) as $label ) {
			$suffix = 'charter-root-key-' . $label . '-' . bin2hex( random_bytes( 6 ) );
			$domain = is_subdomain_install() ? $suffix . '.' . $network->domain : $network->domain;
			$path   = is_subdomain_install() ? $network->path : trailingslashit( $network->path ) . $suffix . '/';
			$result = wp_insert_site(
				array(
					'domain'     => $domain,
					'path'       => $path,
					'network_id' => (int) $network->id,
					'user_id'    => 1,
					'title'      => 'Charter root-key proof',
					'public'     => 0,
				)
			);

			if ( is_wp_error( $result ) ) {
				throw new RuntimeException( 'A sibling site could not be created.' );
			}
			$site_ids[] = $result;
		}

		return array( $site_ids[0], $site_ids[1] );
	}

	/**
	 * Returns public request contexts for the fresh sibling bootstraps.
	 *
	 * @param array{0: int, 1: int} $site_ids Sibling site IDs.
	 * @return array{0: array{domain: string, path: string}, 1: array{domain: string, path: string}}
	 * @throws RuntimeException When a sibling site is unavailable.
	 */
	private static function requestContextsForSites( array $site_ids ): array {
		$contexts = array();

		foreach ( $site_ids as $site_id ) {
			$site = get_site( $site_id );
			if ( null === $site ) {
				throw new RuntimeException( 'A sibling request context is unavailable.' );
			}

			$contexts[] = array(
				'domain' => $site->domain,
				'path'   => $site->path,
			);
		}

		return array( $contexts[0], $contexts[1] );
	}

	/**
	 * Produces an ephemeral comparison tag that is never emitted.
	 *
	 * @param array<string, string> $values Secret values retained in this process.
	 */
	private static function comparisonTag( array $values ): string {
		$context = hash_init( 'sha256' );
		foreach ( $values as $name => $value ) {
			hash_update( $context, pack( 'N', strlen( $name ) ) . $name );
			hash_update( $context, pack( 'N', strlen( $value ) ) . $value );
		}

		return hash_final( $context );
	}

	/**
	 * Writes only ephemeral comparison tags and site locators.
	 *
	 * @param string               $state_file Private temporary comparison-state path.
	 * @param array<string, mixed> $state      State to write.
	 * @throws RuntimeException When the private comparison state cannot be written.
	 */
	private static function writeState( string $state_file, array $state ): void {
		// phpcs:ignore WordPress.WP.AlternativeFunctions.json_encode_json_encode -- The standalone worker may run before WordPress is loaded.
		$encoded = json_encode( $state, JSON_THROW_ON_ERROR );
		// phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_file_put_contents -- Writes one mode-restricted disposable comparison file.
		if ( false === file_put_contents( $state_file, $encoded, LOCK_EX ) ) {
			throw new RuntimeException( 'Probe comparison state could not be written.' );
		}
		// phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_chmod -- Restricts the standalone disposable comparison file.
		chmod( $state_file, 0600 );
	}

	/**
	 * Reads private comparison state without emitting it.
	 *
	 * @param string $state_file Private temporary comparison-state path.
	 * @return array<string, mixed>
	 */
	private static function readState( string $state_file ): array {
		// phpcs:ignore WordPress.WP.AlternativeFunctions.file_get_contents_file_get_contents -- Reads one local disposable comparison file.
		$encoded = file_get_contents( $state_file );
		if ( false === $encoded || '' === $encoded ) {
			return array();
		}

		$state = json_decode( $encoded, true, 8, JSON_THROW_ON_ERROR );

		if ( ! is_array( $state ) ) {
			return array();
		}

		$validated_state = array();

		foreach ( $state as $key => $value ) {
			if ( is_string( $key ) ) {
				$validated_state[ $key ] = $value;
			}
		}

		return $validated_state;
	}
}

ob_start();

$charter_probe_phase      = isset( $argv[1] ) ? (string) $argv[1] : '';
$charter_probe_state_file = isset( $argv[2] ) ? (string) $argv[2] : '';

try {
	$charter_probe_result = ProbeWorker::run( $charter_probe_phase, $charter_probe_state_file );
	$charter_probe_passed = ! in_array( false, $charter_probe_result, true );
} catch ( Throwable ) {
	$charter_probe_result = array( 'passed' => false );
	$charter_probe_passed = false;
}

while ( 0 < ob_get_level() ) {
	ob_end_clean();
}

// phpcs:ignore WordPress.WP.AlternativeFunctions.json_encode_json_encode -- Emits the standalone worker's fixed boolean-only contract.
echo json_encode(
	array(
		'passed' => $charter_probe_passed,
		'checks' => $charter_probe_result,
	),
	JSON_THROW_ON_ERROR
);
exit( $charter_probe_passed ? 0 : 1 );
