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
use GalatanOvidiu\Charter\Admin\NetworkAdminPage;
use GalatanOvidiu\Charter\Admin\NetworkSiteControl;
use GalatanOvidiu\Charter\Http\AuthorizationController;
use GalatanOvidiu\Charter\Http\BoundedDirectJsonFetcher;
use GalatanOvidiu\Charter\Http\CorsPolicy;
use GalatanOvidiu\Charter\Http\MetadataController;
use GalatanOvidiu\Charter\Http\RegistrationController;
use GalatanOvidiu\Charter\Http\RevocationController;
use GalatanOvidiu\Charter\Http\TokenController;
use GalatanOvidiu\Charter\OAuth\AuthorizationService;
use GalatanOvidiu\Charter\OAuth\ClientCleanup;
use GalatanOvidiu\Charter\OAuth\ClientMetadataResolver;
use GalatanOvidiu\Charter\OAuth\ClientMetadataSnapshotStore;
use GalatanOvidiu\Charter\OAuth\ClientGovernance;
use GalatanOvidiu\Charter\OAuth\ClientRegistry;
use GalatanOvidiu\Charter\OAuth\CredentialHasher;
use GalatanOvidiu\Charter\OAuth\CredentialStore;
use GalatanOvidiu\Charter\OAuth\DynamicRegistrationService;
use GalatanOvidiu\Charter\OAuth\GrantGovernance;
use GalatanOvidiu\Charter\OAuth\TokenService;
use GalatanOvidiu\Charter\OAuth\UserSecurityEvents;
use GalatanOvidiu\Charter\Rest\BearerAuthenticator;
use GalatanOvidiu\Charter\Security\AuditLog;
use GalatanOvidiu\Charter\Security\BoundedHostResolver;
use GalatanOvidiu\Charter\Security\RateLimiter;
use GalatanOvidiu\Charter\Site\SiteState;
use GalatanOvidiu\Charter\Site\NetworkActivation;

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
	 * Dynamic registration service.
	 *
	 * @var DynamicRegistrationService
	 */
	private readonly DynamicRegistrationService $dynamicRegistration;

	/**
	 * Site client governance.
	 *
	 * @var ClientGovernance
	 */
	private readonly ClientGovernance $clientGovernance;

	/**
	 * Site grant governance.
	 *
	 * @var GrantGovernance
	 */
	private readonly GrantGovernance $grantGovernance;

	/**
	 * Secret-free security ledger.
	 *
	 * @var AuditLog
	 */
	private readonly AuditLog $audit;

	/**
	 * OAuth abuse counters.
	 *
	 * @var RateLimiter
	 */
	private readonly RateLimiter $rateLimiter;

	/**
	 * Reusable validated Client ID Metadata Document projections.
	 *
	 * @var ClientMetadataSnapshotStore
	 */
	private readonly ClientMetadataSnapshotStore $clientMetadataSnapshots;

	/**
	 * Prevents direct construction.
	 *
	 * @since 0.1.0
	 */
	private function __construct() {
		$this->siteState               = new SiteState();
		$this->clients                 = new ClientRegistry();
		$this->credentials             = new CredentialStore( new CredentialHasher() );
		$this->clientMetadataSnapshots = new ClientMetadataSnapshotStore();
		$this->audit                   = new AuditLog();
		$this->rateLimiter             = new RateLimiter();
		$this->clientGovernance        = new ClientGovernance( $this->clients, $this->credentials, $this->audit, $this->clientMetadataSnapshots );
		$this->grantGovernance         = new GrantGovernance( $this->credentials, $this->audit );
		$this->dynamicRegistration     = new DynamicRegistrationService( $this->siteState, $this->clients, $this->rateLimiter, $this->audit );
		$clientMetadata                = new ClientMetadataResolver( $this->clients, $this->clientMetadataSnapshots, new BoundedHostResolver(), new BoundedDirectJsonFetcher() );
		$this->authorization           = new AuthorizationService( $this->siteState, $this->clients, $this->credentials, $clientMetadata, $this->rateLimiter, $this->audit );
		$this->tokens                  = new TokenService( $this->siteState, $this->clients, $this->credentials );
		$this->bearerAuthenticator     = new BearerAuthenticator( $this->siteState, $this->tokens );

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

	/** Returns reusable CIMD projections for bounded cleanup and tests. */
	public function clientMetadataSnapshots(): ClientMetadataSnapshotStore {
		return $this->clientMetadataSnapshots;
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
	 * Returns Dynamic Client Registration for integration and tests.
	 */
	public function dynamicRegistration(): DynamicRegistrationService {
		return $this->dynamicRegistration;
	}

	/**
	 * Returns site-administrator client governance.
	 */
	public function clientGovernance(): ClientGovernance {
		return $this->clientGovernance;
	}

	/** Returns site-administrator grant governance. */
	public function grantGovernance(): GrantGovernance {
		return $this->grantGovernance;
	}

	/**
	 * Returns the secret-free event ledger.
	 */
	public function audit(): AuditLog {
		return $this->audit;
	}

	/**
	 * Returns OAuth abuse counters for bounded cleanup and tests.
	 */
	public function rateLimiter(): RateLimiter {
		return $this->rateLimiter;
	}

	/**
	 * Prepares an existing active single site after a plugin-code upgrade.
	 *
	 * Network-active sites remain Available until explicitly selected.
	 *
	 * @since 0.1.0
	 */
	public function ensureCurrentSiteReady(): void {
		if ( SiteState::AVAILABLE === $this->siteState->state() && NetworkActivation::isActive() ) {
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
		$registration  = new RegistrationController( $this->dynamicRegistration );
		$authorization = new AuthorizationController( $this->siteState, $this->authorization );
		$settings      = new SettingsPage( $this->siteState, $this->clients, $this->credentials, $this->clientGovernance, $this->grantGovernance, $this->audit );
		$connectedApps = new ConnectedAppsPage( $this->siteState, $this->clients, $this->credentials );
		$networkAdmin  = new NetworkAdminPage( new NetworkSiteControl( $this->siteState, $this->credentials, $this->grantGovernance, $this->audit ) );
		$userEvents    = new UserSecurityEvents( $this->siteState, $this->credentials );
		$cors          = new CorsPolicy();
		$cleanup       = new ClientCleanup( $this->siteState, $this->clients, $this->clientGovernance, $this->audit );

		add_action( 'init', array( $metadata, 'registerRewriteRules' ), 1 );
		add_action( 'init', array( $this, 'ensureCurrentSiteReady' ), 2 );
		add_action( 'rest_api_init', array( $metadata, 'registerRoutes' ) );
		add_action( 'rest_api_init', array( $tokens, 'registerRoutes' ) );
		add_action( 'rest_api_init', array( $revocation, 'registerRoutes' ) );
		add_action( 'rest_api_init', array( $registration, 'registerRoutes' ) );
		add_action( 'admin_post_charter_oauth_authorize', array( $authorization, 'handle' ) );
		add_action( 'admin_post_nopriv_charter_oauth_authorize', array( $authorization, 'handleLoggedOut' ) );
		$settings->registerHooks();
		$connectedApps->registerHooks();
		$networkAdmin->registerHooks();
		$userEvents->registerHooks();
		$cors->registerHooks();
		$cleanup->registerHooks();
		$this->bearerAuthenticator->registerHooks();
	}
}
