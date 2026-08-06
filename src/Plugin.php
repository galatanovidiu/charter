<?php
/**
 * Plugin composition root.
 *
 * @package GalatanOvidiu\Charter
 */

declare(strict_types=1);

namespace GalatanOvidiu\Charter;

use GalatanOvidiu\Charter\Admin\SettingsPage;
use GalatanOvidiu\Charter\Admin\ConnectedAppsPage;
use GalatanOvidiu\Charter\Http\AuthorizationController;
use GalatanOvidiu\Charter\Http\CorsPolicy;
use GalatanOvidiu\Charter\Http\MetadataController;
use GalatanOvidiu\Charter\Http\RevocationController;
use GalatanOvidiu\Charter\Http\TokenController;
use GalatanOvidiu\Charter\OAuth\AuthorizationService;
use GalatanOvidiu\Charter\OAuth\ClientRegistry;
use GalatanOvidiu\Charter\OAuth\CredentialHasher;
use GalatanOvidiu\Charter\OAuth\CredentialStore;
use GalatanOvidiu\Charter\OAuth\TokenService;
use GalatanOvidiu\Charter\OAuth\UserSecurityEvents;
use GalatanOvidiu\Charter\Rest\BearerAuthenticator;
use GalatanOvidiu\Charter\Site\SiteState;

/**
 * Coordinates Charter's feature modules.
 *
 * Feature modules register their hooks here when their implementations exist.
 *
 * @since 0.1.0
 */
final class Plugin {

	/**
	 * Current plugin instance.
	 *
	 * @since 0.1.0
	 *
	 * @var self|null
	 */
	private static ?self $instance = null;

	/**
	 * Site lifecycle and identity service.
	 *
	 * @since 0.1.0
	 *
	 * @var SiteState
	 */
	private readonly SiteState $siteState;

	/**
	 * Pre-registered client service.
	 *
	 * @since 0.1.0
	 *
	 * @var ClientRegistry
	 */
	private readonly ClientRegistry $clients;

	/**
	 * Credential persistence service.
	 *
	 * @since 0.1.0
	 *
	 * @var CredentialStore
	 */
	private readonly CredentialStore $credentials;

	/**
	 * Authorization flow service.
	 *
	 * @since 0.1.0
	 *
	 * @var AuthorizationService
	 */
	private readonly AuthorizationService $authorization;

	/**
	 * Token exchange and validation service.
	 *
	 * @since 0.1.0
	 *
	 * @var TokenService
	 */
	private readonly TokenService $tokens;

	/**
	 * Matched-handler Bearer authentication boundary.
	 *
	 * @since 0.1.0
	 *
	 * @var BearerAuthenticator
	 */
	private readonly BearerAuthenticator $bearerAuthenticator;

	/**
	 * Prevents direct construction.
	 *
	 * @since 0.1.0
	 */
	private function __construct() {
		$this->siteState           = new SiteState();
		$this->clients             = new ClientRegistry();
		$this->credentials         = new CredentialStore( new CredentialHasher() );
		$this->authorization       = new AuthorizationService( $this->siteState, $this->clients, $this->credentials );
		$this->tokens              = new TokenService( $this->siteState, $this->clients, $this->credentials );
		$this->bearerAuthenticator = new BearerAuthenticator( $this->siteState, $this->tokens );

		if ( function_exists( 'add_action' ) ) {
			$this->registerHooks();
		}
	}

	/**
	 * Boots the plugin once and returns its composition root.
	 *
	 * @since 0.1.0
	 *
	 * @return self The plugin composition root.
	 */
	public static function boot(): self {
		if ( null === self::$instance ) {
			self::$instance = new self();
		}

		return self::$instance;
	}

	/**
	 * Prepares a per-site activation without enabling OAuth operations.
	 *
	 * Network activation deliberately leaves each site Available.
	 *
	 * @since 0.1.0
	 *
	 * @param bool $networkWide Whether WordPress is network-activating the plugin.
	 */
	public static function activate( bool $networkWide = false ): void {
		if ( is_multisite() && $networkWide ) {
			return;
		}

		$plugin = self::boot();
		Schema::install();
		$plugin->siteState->prepareCurrentSite();
		( new MetadataController( $plugin->siteState ) )->registerRewriteRules();
		flush_rewrite_rules();
	}

	/**
	 * Returns the site lifecycle service for operator integrations.
	 *
	 * @since 0.1.0
	 */
	public function siteState(): SiteState {
		return $this->siteState;
	}

	/**
	 * Returns the pre-registration service.
	 *
	 * @since 0.1.0
	 */
	public function clients(): ClientRegistry {
		return $this->clients;
	}

	/**
	 * Returns the authorization flow service.
	 *
	 * @since 0.1.0
	 */
	public function authorization(): AuthorizationService {
		return $this->authorization;
	}

	/**
	 * Returns credential persistence for bounded operator and test cleanup.
	 *
	 * @since 0.1.0
	 */
	public function credentials(): CredentialStore {
		return $this->credentials;
	}

	/**
	 * Returns the token service.
	 *
	 * @since 0.1.0
	 */
	public function tokens(): TokenService {
		return $this->tokens;
	}

	/**
	 * Returns the current Bearer request context boundary.
	 *
	 * @since 0.1.0
	 */
	public function bearerAuthenticator(): BearerAuthenticator {
		return $this->bearerAuthenticator;
	}

	/**
	 * Prepares an existing active single site after a plugin-code upgrade.
	 *
	 * Network-active sites remain Available until explicitly selected.
	 *
	 * @since 0.1.0
	 */
	public function ensureCurrentSiteReady(): void {
		$isNetworkActive = false;
		if ( is_multisite() ) {
			$networkPlugins  = get_site_option( 'active_sitewide_plugins', array() );
			$isNetworkActive = is_array( $networkPlugins ) && isset( $networkPlugins[ plugin_basename( CHARTER_FILE ) ] );
		}

		if ( SiteState::AVAILABLE === $this->siteState->state() && $isNetworkActive ) {
			return;
		}

		$installed = Schema::maybeInstall();
		if ( SiteState::AVAILABLE === $this->siteState->state() ) {
			$this->siteState->prepareCurrentSite();
		}
		if ( $installed ) {
			flush_rewrite_rules( false );
		}
	}

	/**
	 * Registers WordPress HTTP hooks.
	 *
	 * @since 0.1.0
	 */
	private function registerHooks(): void {
		$metadata      = new MetadataController( $this->siteState );
		$tokens        = new TokenController( $this->tokens );
		$revocation    = new RevocationController( $this->tokens );
		$authorization = new AuthorizationController( $this->siteState, $this->authorization );
		$settings      = new SettingsPage( $this->siteState, $this->clients );
		$connectedApps = new ConnectedAppsPage( $this->siteState, $this->clients, $this->credentials );
		$userEvents    = new UserSecurityEvents( $this->siteState, $this->credentials );
		$cors          = new CorsPolicy();

		add_action( 'init', array( $metadata, 'registerRewriteRules' ), 1 );
		add_action( 'init', array( $this, 'ensureCurrentSiteReady' ), 2 );
		add_action( 'rest_api_init', array( $metadata, 'registerRoutes' ) );
		add_action( 'rest_api_init', array( $tokens, 'registerRoutes' ) );
		add_action( 'rest_api_init', array( $revocation, 'registerRoutes' ) );
		add_action( 'admin_post_charter_oauth_authorize', array( $authorization, 'handle' ) );
		add_action( 'admin_post_nopriv_charter_oauth_authorize', array( $authorization, 'handleLoggedOut' ) );
		$settings->registerHooks();
		$connectedApps->registerHooks();
		$userEvents->registerHooks();
		$cors->registerHooks();
		$this->bearerAuthenticator->registerHooks();
	}
}
