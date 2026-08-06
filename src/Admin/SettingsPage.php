<?php
/**
 * Minimal site OAuth setup screen.
 *
 * @package GalatanOvidiu\Charter
 */

declare(strict_types=1);

namespace GalatanOvidiu\Charter\Admin;

use GalatanOvidiu\Charter\Http\EndpointUrls;
use GalatanOvidiu\Charter\OAuth\ClientRegistry;
use GalatanOvidiu\Charter\Site\SiteState;
use InvalidArgumentException;
use RuntimeException;

/**
 * Lets a site administrator verify, enable, and pre-register OAuth clients.
 *
 * @since 0.1.0
 */
final class SettingsPage {

	/**
	 * Creates the settings screen.
	 *
	 * @since 0.1.0
	 *
	 * @param SiteState      $siteState Site lifecycle and identity.
	 * @param ClientRegistry $clients   Pre-registered client service.
	 */
	public function __construct(
		private readonly SiteState $siteState,
		private readonly ClientRegistry $clients
	) {
	}

	/**
	 * Registers site administrator hooks.
	 *
	 * @since 0.1.0
	 */
	public function registerHooks(): void {
		add_action( 'admin_menu', array( $this, 'registerPage' ) );
		add_action( 'admin_post_charter_oauth_enable', array( $this, 'enable' ) );
		add_action( 'admin_post_charter_oauth_register_client', array( $this, 'registerClient' ) );
	}

	/**
	 * Adds the Charter OAuth screen under Settings.
	 *
	 * @since 0.1.0
	 */
	public function registerPage(): void {
		add_options_page(
			esc_html__( 'Charter OAuth', 'charter' ),
			esc_html__( 'Charter OAuth', 'charter' ),
			'manage_options',
			'charter-oauth',
			array( $this, 'render' )
		);
	}

	/**
	 * Renders current state and the smallest operational setup controls.
	 *
	 * @since 0.1.0
	 */
	public function render(): void {
		$this->requireAdministrator();

		$identity = $this->siteState->identity();
		?>
		<div class="wrap">
			<h1><?php esc_html_e( 'Charter OAuth', 'charter' ); ?></h1>
			<p><?php /* translators: %s: Current OAuth lifecycle state. */ echo esc_html( sprintf( __( 'State: %s', 'charter' ), ucfirst( $this->siteState->state() ) ) ); ?></p>
			<?php if ( null === $identity ) : ?>
				<div class="notice notice-error"><p><?php esc_html_e( 'The site needs a supported canonical bare-origin public URL before OAuth can be prepared.', 'charter' ); ?></p></div>
			<?php else : ?>
				<p><?php /* translators: %s: Exact canonical OAuth issuer URL. */ echo esc_html( sprintf( __( 'Issuer and default resource: %s', 'charter' ), $identity->issuer() ) ); ?></p>
				<?php $urls = new EndpointUrls( $identity->issuer() ); ?>
				<ul>
					<li><a href="<?php echo esc_url( $urls->authorizationServerMetadata() ); ?>"><?php esc_html_e( 'Authorization server metadata', 'charter' ); ?></a></li>
					<li><a href="<?php echo esc_url( $urls->protectedResourceMetadata() ); ?>"><?php esc_html_e( 'Protected resource metadata', 'charter' ); ?></a></li>
				</ul>

				<?php if ( SiteState::PREPARED === $this->siteState->state() ) : ?>
					<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>">
						<input type="hidden" name="action" value="charter_oauth_enable">
						<input type="hidden" name="issuer" value="<?php echo esc_attr( $identity->issuer() ); ?>">
						<?php wp_nonce_field( 'charter_oauth_enable:' . $identity->issuer() ); ?>
						<label><input type="checkbox" name="discovery_verified" value="1" required> <?php esc_html_e( 'I verified both exact metadata URLs from the intended client environment.', 'charter' ); ?></label>
						<?php submit_button( __( 'Enable OAuth', 'charter' ) ); ?>
					</form>
				<?php endif; ?>

				<h2><?php esc_html_e( 'Pre-register a client', 'charter' ); ?></h2>
				<p><?php esc_html_e( 'Every client uses Authorization Code with mandatory PKCE S256. Confidential clients receive a secret once after registration.', 'charter' ); ?></p>
				<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>">
					<input type="hidden" name="action" value="charter_oauth_register_client">
					<?php wp_nonce_field( 'charter_oauth_register_client:' . $identity->issuer() ); ?>
					<table class="form-table" role="presentation">
						<tr><th><label for="charter-client-id"><?php esc_html_e( 'Client ID', 'charter' ); ?></label></th><td><input class="regular-text" id="charter-client-id" name="client_id" required></td></tr>
						<tr><th><label for="charter-client-name"><?php esc_html_e( 'Client name', 'charter' ); ?></label></th><td><input class="regular-text" id="charter-client-name" name="client_name" required></td></tr>
						<tr><th><label for="charter-redirect-uri"><?php esc_html_e( 'Redirect URI', 'charter' ); ?></label></th><td><input class="regular-text code" id="charter-redirect-uri" name="redirect_uri" type="url" required></td></tr>
						<tr>
							<th><label for="charter-client-type"><?php esc_html_e( 'Client type', 'charter' ); ?></label></th>
							<td>
								<select id="charter-client-type" name="client_type">
									<option value="public"><?php esc_html_e( 'Public (no secret)', 'charter' ); ?></option>
									<option value="confidential"><?php esc_html_e( 'Confidential (client secret)', 'charter' ); ?></option>
								</select>
							</td>
						</tr>
						<tr><th><?php esc_html_e( 'Continuing access', 'charter' ); ?></th><td><label><input type="checkbox" name="supports_refresh" value="1" checked> <?php esc_html_e( 'Allow the client to receive rotating refresh tokens after user consent.', 'charter' ); ?></label></td></tr>
					</table>
					<?php submit_button( __( 'Register client', 'charter' ) ); ?>
				</form>
			<?php endif; ?>
		</div>
		<?php
	}

	/**
	 * Records exact metadata verification and enables this issuer.
	 *
	 * @since 0.1.0
	 */
	public function enable(): void {
		$this->requireAdministrator();
		$issuer = self::postScalar( 'issuer' );
		check_admin_referer( 'charter_oauth_enable:' . $issuer );

		if (
			'1' !== self::postScalar( 'discovery_verified' )
			|| ! $this->siteState->recordDiscoveryVerification( $issuer )
			|| ! $this->siteState->enable( $issuer )
		) {
			wp_die( esc_html__( 'The exact prepared issuer could not be enabled.', 'charter' ), '', array( 'response' => 400 ) );
		}

		wp_safe_redirect( $this->settingsUrl() );
		exit;
	}

	/**
	 * Persists one immutable issuer-bound client registration.
	 *
	 * @since 0.1.0
	 */
	public function registerClient(): void {
		$this->requireAdministrator();
		$identity = $this->siteState->identity();
		if ( null === $identity ) {
			wp_die( esc_html__( 'The site OAuth issuer is not prepared.', 'charter' ), '', array( 'response' => 400 ) );
		}

		check_admin_referer( 'charter_oauth_register_client:' . $identity->issuer() );

		$clientType      = self::postScalar( 'client_type' );
		$supportsRefresh = '1' === self::postScalar( 'supports_refresh' );
		if ( ! in_array( $clientType, array( 'public', 'confidential' ), true ) ) {
			wp_die( esc_html__( 'The client type is invalid.', 'charter' ), '', array( 'response' => 400 ) );
		}

		try {
			$arguments = array(
				$identity->issuer(),
				self::postScalar( 'client_id' ),
				self::postScalar( 'client_name' ),
				array( self::postScalar( 'redirect_uri' ) ),
				$supportsRefresh,
			);
			if ( 'confidential' === $clientType ) {
				$secret = $this->clients->registerConfidentialClient( ...$arguments );
				$this->renderClientSecret( $arguments[1], $secret );
			}

			$registered = $this->clients->registerPublicClient( ...$arguments );
		} catch ( InvalidArgumentException ) {
			wp_die( esc_html__( 'The client registration is invalid or changes an existing client identity.', 'charter' ), '', array( 'response' => 400 ) );
		} catch ( RuntimeException ) {
			wp_die( esc_html__( 'The client registration could not be saved.', 'charter' ), '', array( 'response' => 500 ) );
		}
		if ( ! $registered ) {
			wp_die( esc_html__( 'The client registration could not be saved.', 'charter' ), '', array( 'response' => 500 ) );
		}

		wp_safe_redirect( $this->settingsUrl() );
		exit;
	}

	/**
	 * Reveals a generated confidential-client secret in one no-store response.
	 *
	 * Refreshing the POST cannot reveal the secret again because registrations
	 * are immutable and only its password hash was persisted.
	 *
	 * @since 0.1.0
	 *
	 * @param string $clientId Registered client identifier.
	 * @param string $secret   Newly generated client secret.
	 */
	private function renderClientSecret( string $clientId, string $secret ): never {
		status_header( 200 );
		nocache_headers();
		header( 'Referrer-Policy: no-referrer' );
		header( "Content-Security-Policy: default-src 'none'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'" );
		?>
		<!doctype html>
		<html <?php language_attributes(); ?>>
		<head><meta charset="<?php bloginfo( 'charset' ); ?>"><meta name="viewport" content="width=device-width, initial-scale=1"><title><?php esc_html_e( 'Client registered', 'charter' ); ?></title></head>
		<body>
			<main>
				<h1><?php esc_html_e( 'Save this client secret now', 'charter' ); ?></h1>
				<p><?php /* translators: %s: Client identifier. */ echo esc_html( sprintf( __( 'Confidential client %s was registered.', 'charter' ), $clientId ) ); ?></p>
				<p><?php esc_html_e( 'This secret cannot be retrieved after you leave this page.', 'charter' ); ?></p>
				<p><code><?php echo esc_html( $secret ); ?></code></p>
				<p><a href="<?php echo esc_url( $this->settingsUrl() ); ?>"><?php esc_html_e( 'Return to Charter OAuth settings', 'charter' ); ?></a></p>
			</main>
		</body>
		</html>
		<?php
		exit;
	}

	/**
	 * Enforces site-administrator ownership.
	 *
	 * @since 0.1.0
	 */
	private function requireAdministrator(): void {
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_die( esc_html__( 'You are not allowed to manage Charter OAuth.', 'charter' ), '', array( 'response' => 403 ) );
		}
	}

	/**
	 * Reads one unslashed scalar POST value.
	 *
	 * @since 0.1.0
	 *
	 * @param string $name Field name.
	 */
	private static function postScalar( string $name ): string {
		$value = $_POST[ $name ] ?? null; // phpcs:ignore WordPress.Security.NonceVerification.Missing -- Each action verifies its form nonce before using security-sensitive values.

		return is_string( $value ) ? wp_unslash( $value ) : '';
	}

	/**
	 * Returns the site settings URL.
	 *
	 * @since 0.1.0
	 */
	private function settingsUrl(): string {
		return admin_url( 'options-general.php?page=charter-oauth&updated=1' );
	}
}
