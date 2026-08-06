<?php
/**
 * Minimal site OAuth setup screen.
 *
 * @package GalatanOvidiu\Charter
 */

declare(strict_types=1);

namespace GalatanOvidiu\Charter\Admin;

use GalatanOvidiu\Charter\Http\EndpointUrls;
use GalatanOvidiu\Charter\OAuth\ClientGovernance;
use GalatanOvidiu\Charter\OAuth\ClientRegistry;
use GalatanOvidiu\Charter\OAuth\CredentialStore;
use GalatanOvidiu\Charter\OAuth\DynamicRegistrationService;
use GalatanOvidiu\Charter\Security\AuditLog;
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
	 * @param SiteState        $siteState Site lifecycle and identity.
	 * @param ClientRegistry   $clients   Client registry.
	 * @param CredentialStore  $credentials Grant persistence.
	 * @param ClientGovernance $governance Administrator governance.
	 * @param AuditLog         $audit Security event ledger.
	 */
	public function __construct(
		private readonly SiteState $siteState,
		private readonly ClientRegistry $clients,
		private readonly CredentialStore $credentials,
		private readonly ClientGovernance $governance,
		private readonly AuditLog $audit
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
		add_action( 'admin_post_charter_oauth_update_dcr', array( $this, 'updateDynamicRegistration' ) );
		add_action( 'admin_post_charter_oauth_block_client', array( $this, 'blockClient' ) );
		add_action( 'admin_post_charter_oauth_delete_client', array( $this, 'deleteClient' ) );
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
		$clients  = null === $identity ? array() : $this->clients->listForIssuer( $identity->issuer() );
		$events   = null === $identity ? array() : $this->audit->listForIssuer( $identity->issuer(), 50 );
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

				<h2><?php esc_html_e( 'Dynamic Client Registration', 'charter' ); ?></h2>
				<p><?php esc_html_e( 'Dynamic registration is enabled by default for compatible clients. Disabling it stops only new registrations and does not revoke existing clients or grants.', 'charter' ); ?></p>
				<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>">
					<input type="hidden" name="action" value="charter_oauth_update_dcr">
					<?php wp_nonce_field( 'charter_oauth_update_dcr:' . $identity->issuer() ); ?>
					<label><input type="checkbox" name="dcr_enabled" value="1" <?php checked( DynamicRegistrationService::isEnabled() ); ?>> <?php esc_html_e( 'Accept new dynamic registrations', 'charter' ); ?></label>
					<?php submit_button( __( 'Save registration policy', 'charter' ) ); ?>
				</form>

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

				<h2><?php esc_html_e( 'Registered clients', 'charter' ); ?></h2>
				<?php if ( array() === $clients ) : ?>
					<p><?php esc_html_e( 'No clients are registered for this issuer.', 'charter' ); ?></p>
				<?php else : ?>
					<table class="widefat striped">
						<thead><tr><th><?php esc_html_e( 'Client', 'charter' ); ?></th><th><?php esc_html_e( 'Registration', 'charter' ); ?></th><th><?php esc_html_e( 'Authorizations', 'charter' ); ?></th><th><?php esc_html_e( 'Action', 'charter' ); ?></th></tr></thead>
						<tbody>
						<?php foreach ( $clients as $client ) : ?>
							<?php $grants = $this->credentials->listActiveGrantsForClient( $identity->issuer(), $client->clientId() ); ?>
							<tr>
								<td><strong><?php echo esc_html( $client->name() ); ?></strong><br><code><?php echo esc_html( $client->clientId() ); ?></code></td>
								<td><?php /* translators: 1: registration source, 2: lifecycle status. */ echo esc_html( sprintf( __( '%1$s; %2$s', 'charter' ), $client->source(), $client->status() ) ); ?><br><?php echo esc_html( $client->authenticationMethod() ); ?></td>
								<td>
									<?php if ( array() === $grants ) : ?>
										<?php esc_html_e( 'No active grants', 'charter' ); ?>
									<?php else : ?>
										<?php foreach ( $grants as $grant ) : ?>
											<?php $user = get_userdata( $grant->userId() ); ?>
											<div><?php echo esc_html( false === $user ? (string) $grant->userId() : $user->display_name ); ?> — <?php echo esc_html( $grant->scope() ); ?></div>
										<?php endforeach; ?>
									<?php endif; ?>
								</td>
								<td>
									<?php if ( ClientRegistry::STATUS_ACTIVE === $client->status() ) : ?>
										<?php $this->renderClientAction( 'charter_oauth_block_client', __( 'Block', 'charter' ), $identity->issuer(), $client->clientId(), 'secondary' ); ?>
									<?php endif; ?>
									<?php if ( ClientRegistry::STATUS_DELETED !== $client->status() ) : ?>
										<?php $this->renderClientAction( 'charter_oauth_delete_client', __( 'Delete', 'charter' ), $identity->issuer(), $client->clientId(), 'delete' ); ?>
									<?php endif; ?>
								</td>
							</tr>
						<?php endforeach; ?>
						</tbody>
					</table>
				<?php endif; ?>

				<h2><?php esc_html_e( 'Recent OAuth security events', 'charter' ); ?></h2>
				<?php if ( array() === $events ) : ?>
					<p><?php esc_html_e( 'No security events are recorded for this issuer.', 'charter' ); ?></p>
				<?php else : ?>
					<table class="widefat striped"><thead><tr><th><?php esc_html_e( 'Time', 'charter' ); ?></th><th><?php esc_html_e( 'Event', 'charter' ); ?></th><th><?php esc_html_e( 'Client', 'charter' ); ?></th><th><?php esc_html_e( 'Outcome', 'charter' ); ?></th></tr></thead><tbody>
					<?php foreach ( $events as $event ) : ?>
						<?php $eventTime = wp_date( 'Y-m-d H:i:s', $event->occurredAt() ); ?>
						<tr><td><?php echo esc_html( false === $eventTime ? '' : $eventTime ); ?></td><td><?php echo esc_html( $event->eventType() ); ?><br><?php echo esc_html( $event->reason() ); ?></td><td><code><?php echo esc_html( $event->clientId() ?? '—' ); ?></code></td><td><?php echo esc_html( $event->outcome() ); ?></td></tr>
					<?php endforeach; ?>
					</tbody></table>
				<?php endif; ?>
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
	 * Enables or stops only new Dynamic Client Registration.
	 */
	public function updateDynamicRegistration(): void {
		$this->requireAdministrator();
		$identity = $this->requireIdentity();
		check_admin_referer( 'charter_oauth_update_dcr:' . $identity->issuer() );
		if ( ! DynamicRegistrationService::setEnabled( '1' === self::postScalar( 'dcr_enabled' ) ) ) {
			wp_die( esc_html__( 'The dynamic registration policy could not be saved.', 'charter' ), '', array( 'response' => 500 ) );
		}

		wp_safe_redirect( $this->settingsUrl() );
		exit;
	}

	/**
	 * Blocks one exact issuer-owned client and revokes its active grants.
	 */
	public function blockClient(): void {
		$this->governClient( 'block' );
	}

	/**
	 * Deletes one exact issuer-owned client and revokes its active grants.
	 */
	public function deleteClient(): void {
		$this->governClient( 'delete' );
	}

	/**
	 * Applies one nonce-protected administrator client action.
	 *
	 * @param string $operation Block or delete.
	 */
	private function governClient( string $operation ): never {
		$this->requireAdministrator();
		$identity = $this->requireIdentity();
		$clientId = self::postScalar( 'client_id' );
		$action   = 'charter_oauth_' . $operation . '_client';
		check_admin_referer( $action . ':' . hash( 'sha256', $identity->issuer() . "\0" . $clientId ) );

		$completed = 'block' === $operation
			? $this->governance->block( $identity->issuer(), $clientId, get_current_user_id(), time() )
			: $this->governance->delete( $identity->issuer(), $clientId, get_current_user_id(), time() );
		if ( ! $completed ) {
			wp_die( esc_html__( 'The client governance action could not be completed.', 'charter' ), '', array( 'response' => 400 ) );
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
	 * Returns the prepared current identity or stops the administrator action.
	 */
	private function requireIdentity(): \GalatanOvidiu\Charter\Site\SiteIdentity {
		$identity = $this->siteState->identity();
		if ( null === $identity ) {
			wp_die( esc_html__( 'The site OAuth issuer is not prepared.', 'charter' ), '', array( 'response' => 400 ) );
		}

		return $identity;
	}

	/**
	 * Renders one exact client governance form.
	 *
	 * @param string $action Admin-post action.
	 * @param string $label Button label.
	 * @param string $issuer Exact issuer.
	 * @param string $clientId Exact client identifier.
	 * @param string $buttonClass WordPress button class.
	 */
	private function renderClientAction( string $action, string $label, string $issuer, string $clientId, string $buttonClass ): void {
		?>
		<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>" style="display:inline-block">
			<input type="hidden" name="action" value="<?php echo esc_attr( $action ); ?>">
			<input type="hidden" name="client_id" value="<?php echo esc_attr( $clientId ); ?>">
			<?php wp_nonce_field( $action . ':' . hash( 'sha256', $issuer . "\0" . $clientId ) ); ?>
			<?php submit_button( $label, $buttonClass . ' small', 'submit', false ); ?>
		</form>
		<?php
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
