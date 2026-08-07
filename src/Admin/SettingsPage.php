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
use GalatanOvidiu\Charter\OAuth\EmergencyContainment;
use GalatanOvidiu\Charter\OAuth\GrantGovernance;
use GalatanOvidiu\Charter\OAuth\GrantRecord;
use GalatanOvidiu\Charter\OAuth\SigningKeyLifecycle;
use GalatanOvidiu\Charter\Security\AuditLog;
use GalatanOvidiu\Charter\Site\NetworkActivation;
use GalatanOvidiu\Charter\Site\SiteState;
use InvalidArgumentException;
use RuntimeException;

/**
 * Lets a site administrator verify, enable, and pre-register OAuth clients.
 *
 * @since 0.1.0
 */
final class SettingsPage {

	private const CONTAINMENT_ACTION = 'charter_oauth_set_emergency_mode';
	private const ADOPT_KEY_ACTION   = 'charter_oauth_adopt_signing_key';
	private const KEY_AUDIT_ACTION   = 'charter_oauth_reconcile_signing_key_audit';

	/**
	 * Exact WordPress hook suffix for this screen.
	 *
	 * @var string|null
	 */
	private ?string $pageHook = null;

	/**
	 * Creates the settings screen.
	 *
	 * @since 0.1.0
	 *
	 * @param SiteState            $siteState Site lifecycle and identity.
	 * @param ClientRegistry       $clients   Client registry.
	 * @param CredentialStore      $credentials Grant persistence.
	 * @param ClientGovernance     $governance Administrator governance.
	 * @param GrantGovernance      $grantGovernance Administrator grant governance.
	 * @param AuditLog             $audit Security event ledger.
	 * @param EmergencyContainment $containment Issuer-local emergency mode.
	 * @param SigningKeyLifecycle  $signingKeys Issuer-local credential-key lifecycle.
	 */
	public function __construct(
		private readonly SiteState $siteState,
		private readonly ClientRegistry $clients,
		private readonly CredentialStore $credentials,
		private readonly ClientGovernance $governance,
		private readonly GrantGovernance $grantGovernance,
		private readonly AuditLog $audit,
		private readonly EmergencyContainment $containment,
		private readonly SigningKeyLifecycle $signingKeys
	) {
	}

	/**
	 * Registers site administrator hooks.
	 *
	 * @since 0.1.0
	 */
	public function registerHooks(): void {
		add_action( 'admin_menu', array( $this, 'registerPage' ) );
		add_action( 'admin_enqueue_scripts', array( $this, 'enqueueAssets' ) );
		add_action( 'admin_post_charter_oauth_enable', array( $this, 'enable' ) );
		add_action( 'admin_post_charter_oauth_register_client', array( $this, 'registerClient' ) );
		add_action( 'admin_post_charter_oauth_update_dcr', array( $this, 'updateDynamicRegistration' ) );
		add_action( 'admin_post_charter_oauth_block_client', array( $this, 'blockClient' ) );
		add_action( 'admin_post_charter_oauth_delete_client', array( $this, 'deleteClient' ) );
		add_action( 'admin_post_charter_oauth_revoke_site_grant', array( $this, 'revokeGrant' ) );
		add_action( 'admin_post_charter_oauth_revoke_all_site_grants', array( $this, 'revokeAllGrants' ) );
		add_action( 'admin_post_' . self::CONTAINMENT_ACTION, array( $this, 'setContainmentMode' ) );
		add_action( 'admin_post_' . self::ADOPT_KEY_ACTION, array( $this, 'adoptSigningKey' ) );
		add_action( 'admin_post_' . self::KEY_AUDIT_ACTION, array( $this, 'reconcileSigningKeyAudit' ) );
		add_action( 'admin_notices', array( $this, 'renderLockdownNotice' ) );
	}

	/**
	 * Adds the Charter OAuth screen under Settings.
	 *
	 * @since 0.1.0
	 */
	public function registerPage(): void {
		$pageHook       = add_options_page(
			esc_html__( 'Charter OAuth', 'charter' ),
			esc_html__( 'Charter OAuth', 'charter' ),
			'manage_options',
			'charter-oauth',
			array( $this, 'render' )
		);
		$this->pageHook = is_string( $pageHook ) ? $pageHook : null;
	}

	/**
	 * Loads the component application only on the Charter site screen.
	 *
	 * @param string $hookSuffix Current WordPress administration screen hook.
	 */
	public function enqueueAssets( string $hookSuffix ): void {
		if ( null !== $this->pageHook && $this->pageHook === $hookSuffix ) {
			AdminAssets::enqueue( 'site-admin' );
		}
	}

	/**
	 * Renders current state and the smallest operational setup controls.
	 *
	 * @since 0.1.0
	 */
	public function render(): void {
		$this->requireAdministrator();
		$networkActivationRequired = is_multisite() && ! NetworkActivation::isActive();
		if ( $networkActivationRequired ) {
			?>
			<div class="wrap">
				<h1><?php esc_html_e( 'Charter OAuth', 'charter' ); ?></h1>
				<div class="notice notice-error"><p><?php esc_html_e( 'Charter OAuth requires Network Activation on WordPress Multisite so each site issuer can be governed and permanently deleted without retaining hidden OAuth tables.', 'charter' ); ?></p></div>
				<p><?php esc_html_e( 'Ask a Network Administrator to network-activate Charter, then prepare this site under Network Settings > Charter OAuth.', 'charter' ); ?></p>
			</div>
			<?php

			return;
		}

		$identity   = $this->siteState->identity();
		$clients    = null === $identity ? array() : $this->clients->listForIssuer( $identity->issuer() );
		$events     = null === $identity ? array() : $this->audit->listForIssuer( $identity->issuer(), 50 );
		$grantCount = null === $identity ? 0 : $this->credentials->countActiveGrantsForIssuer( $identity->issuer() );
		$grantPage  = max( 1, absint( self::getScalar( 'grant_page' ) ) );
		$grantPages = max( 1, (int) ceil( $grantCount / 50 ) );
		$grantPage  = min( $grantPage, $grantPages );
		$grants     = null === $identity ? array() : $this->credentials->listActiveGrantsForIssuer( $identity->issuer(), 50, ( $grantPage - 1 ) * 50 );
		$viewData   = $this->viewData( $identity, $clients, $events, $grantCount, $grantPage, $grantPages, $grants );
		?>
		<div class="wrap charter-admin-mount">
			<div id="charter-site-admin-root"><p role="status"><?php esc_html_e( 'Loading Charter OAuth…', 'charter' ); ?></p></div>
			<?php AdminAssets::renderData( 'charter-site-admin-data', $viewData ); ?>
		</div>
		<noscript>
		<div class="wrap">
			<h1><?php esc_html_e( 'Charter OAuth', 'charter' ); ?></h1>
			<?php if ( 'pending' === self::getScalar( 'containment_audit' ) ) : ?>
				<div class="notice notice-warning"><p><?php esc_html_e( 'The requested OAuth emergency mode is active, but its audit event is pending reconciliation. Retry the same mode after restoring the audit ledger.', 'charter' ); ?></p></div>
			<?php endif; ?>
			<?php if ( 'adopted' === self::getScalar( 'signing_key' ) ) : ?>
				<div class="notice notice-success"><p><?php esc_html_e( 'The exact current explicit Charter key replacement was adopted for this site issuer. Credentials from earlier explicit-key generations remain unusable.', 'charter' ); ?></p></div>
			<?php elseif ( 'reconciled' === self::getScalar( 'signing_key' ) ) : ?>
				<div class="notice notice-success"><p><?php esc_html_e( 'The pending explicit-key adoption audit event was reconciled.', 'charter' ); ?></p></div>
			<?php endif; ?>
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

				<?php if ( $this->siteState->isEnabled() ) : ?>
					<?php $this->renderSigningKeyControls( $identity->issuer() ); ?>
					<?php $this->renderContainmentControls( $identity->issuer() ); ?>
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

				<h2><?php esc_html_e( 'Site authorizations', 'charter' ); ?></h2>
				<p><?php /* translators: %d: Number of active OAuth grants. */ echo esc_html( sprintf( _n( '%d active authorization is issued in users’ names on this site.', '%d active authorizations are issued in users’ names on this site.', $grantCount, 'charter' ), $grantCount ) ); ?></p>
				<?php if ( array() === $grants ) : ?>
					<p><?php esc_html_e( 'No active OAuth authorizations exist for this issuer.', 'charter' ); ?></p>
				<?php else : ?>
					<table class="widefat striped">
						<thead><tr><th><?php esc_html_e( 'Application', 'charter' ); ?></th><th><?php esc_html_e( 'Authorization', 'charter' ); ?></th><th><?php esc_html_e( 'Activity', 'charter' ); ?></th><th><?php esc_html_e( 'Action', 'charter' ); ?></th></tr></thead>
						<tbody>
						<?php $renderedUserId = 0; ?>
						<?php foreach ( $grants as $grant ) : ?>
							<?php if ( $renderedUserId !== $grant->userId() ) : ?>
								<?php $renderedUserId = $grant->userId(); ?>
								<tr><th colspan="4"><?php echo esc_html( $this->userLabel( $grant->userId() ) ); ?></th></tr>
							<?php endif; ?>
							<tr>
								<td><strong><?php echo esc_html( $this->clientName( $grant ) ); ?></strong><br><code><?php echo esc_html( $grant->clientId() ); ?></code></td>
								<td><?php /* translators: %s: Exact OAuth protected resource URL. */ echo esc_html( sprintf( __( 'Resource: %s', 'charter' ), $grant->resource() ) ); ?><br><?php /* translators: %s: Space-delimited OAuth scope identifiers. */ echo esc_html( sprintf( __( 'Scopes: %s', 'charter' ), $grant->scope() ) ); ?><br><?php echo esc_html( $grant->continuingAccess() ? __( 'Continuing access: Yes', 'charter' ) : __( 'Continuing access: No', 'charter' ) ); ?></td>
								<td><?php /* translators: %s: Localized authorization date and time. */ echo esc_html( sprintf( __( 'Authorized: %s', 'charter' ), $this->formatTimestamp( $grant->authorizedAt() ) ) ); ?><br><?php /* translators: %s: Localized last activity date and time. */ echo esc_html( sprintf( __( 'Last activity: %s', 'charter' ), $this->formatTimestamp( $grant->lastUsedAt() ) ) ); ?></td>
								<td><?php $this->renderGrantAction( $identity->issuer(), $grant->id() ); ?></td>
							</tr>
						<?php endforeach; ?>
						</tbody>
					</table>
					<?php $this->renderGrantPagination( $grantPage, $grantPages ); ?>
					<h3><?php esc_html_e( 'Revoke all site access', 'charter' ); ?></h3>
					<p><?php esc_html_e( 'This permanently disconnects every active OAuth authorization for this site. Client registrations remain available for users to authorize again.', 'charter' ); ?></p>
					<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>">
						<input type="hidden" name="action" value="charter_oauth_revoke_all_site_grants">
						<?php wp_nonce_field( 'charter_oauth_revoke_all_site_grants:' . hash( 'sha256', $identity->issuer() ) ); ?>
						<label><input type="checkbox" name="confirm_revocation" value="1" required> <?php esc_html_e( 'I understand that all active site authorizations will be revoked.', 'charter' ); ?></label>
						<?php submit_button( __( 'Revoke all OAuth grants', 'charter' ), 'delete', 'submit', false ); ?>
					</form>
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
		</noscript>
		<?php
	}

	/**
	 * Builds the secret-free presentation model for the site administrator app.
	 *
	 * @param \GalatanOvidiu\Charter\Site\SiteIdentity|null                $identity Prepared identity.
	 * @param array<\GalatanOvidiu\Charter\OAuth\ClientRegistrationRecord> $clients Registered clients.
	 * @param array<\GalatanOvidiu\Charter\Security\AuditEvent>            $events Recent audit events.
	 * @param int                                                          $grantCount Complete active grant count.
	 * @param int                                                          $grantPage Current grant page.
	 * @param int                                                          $grantPages Total grant pages.
	 * @param array<GrantRecord>                                           $grants Bounded active grants.
	 * @return array<string, mixed>
	 */
	private function viewData( ?\GalatanOvidiu\Charter\Site\SiteIdentity $identity, array $clients, array $events, int $grantCount, int $grantPage, int $grantPages, array $grants ): array {
		$issuer      = null === $identity ? '' : $identity->issuer();
		$state       = $this->siteState->state();
		$enabled     = $this->siteState->isEnabled();
		$containment = $enabled ? $this->containment->snapshot() : null;
		$signingKey  = $enabled ? $this->signingKeys->snapshot() : null;
		$urls        = null === $identity ? null : new EndpointUrls( $issuer );

		$clientRows = array();
		foreach ( $clients as $client ) {
			$clientGrants = $this->credentials->listActiveGrantsForClient( $issuer, $client->clientId() );
			$actions      = array();
			if ( ClientRegistry::STATUS_ACTIVE === $client->status() ) {
				$actions['block'] = self::postAction(
					'charter_oauth_block_client',
					'charter_oauth_block_client:' . hash( 'sha256', $issuer . "\0" . $client->clientId() ),
					array( 'client_id' => $client->clientId() )
				);
			}
			if ( ClientRegistry::STATUS_DELETED !== $client->status() ) {
				$actions['delete'] = self::postAction(
					'charter_oauth_delete_client',
					'charter_oauth_delete_client:' . hash( 'sha256', $issuer . "\0" . $client->clientId() ),
					array( 'client_id' => $client->clientId() )
				);
			}

			$clientRows[] = array(
				'id'                   => $client->clientId(),
				'name'                 => $client->name(),
				'status'               => $client->status(),
				'source'               => $client->source(),
				'authenticationMethod' => $client->authenticationMethod(),
				'redirectUris'         => $client->redirectUris(),
				'createdAt'            => $this->formatTimestamp( $client->createdAt() ),
				'lastActivityAt'       => $this->formatTimestamp( $client->lastActivityAt() ),
				'activeGrants'         => array_map(
					function ( GrantRecord $grant ): array {
						return array(
							'user'  => $this->userLabel( $grant->userId() ),
							'scope' => $grant->scope(),
						);
					},
					$clientGrants
				),
				'actions'              => $actions,
			);
		}

		$grantRows = array_map(
			function ( GrantRecord $grant ) use ( $issuer ): array {
				return array(
					'id'               => $grant->id(),
					'user'             => $this->userLabel( $grant->userId() ),
					'application'      => $this->clientName( $grant ),
					'clientId'         => $grant->clientId(),
					'resource'         => $grant->resource(),
					'scope'            => $grant->scope(),
					'continuingAccess' => $grant->continuingAccess(),
					'authorizedAt'     => $this->formatTimestamp( $grant->authorizedAt() ),
					'lastUsedAt'       => $this->formatTimestamp( $grant->lastUsedAt() ),
					'action'           => self::postAction(
						'charter_oauth_revoke_site_grant',
						'charter_oauth_revoke_site_grant:' . hash( 'sha256', $issuer . "\0" . $grant->id() ),
						array( 'grant_id' => (string) $grant->id() )
					),
				);
			},
			$grants
		);

		$eventRows = array_map(
			function ( \GalatanOvidiu\Charter\Security\AuditEvent $event ): array {
				return array(
					'time'    => $this->formatTimestamp( $event->occurredAt() ),
					'type'    => $event->eventType(),
					'reason'  => $event->reason(),
					'client'  => $event->clientId(),
					'outcome' => $event->outcome(),
				);
			},
			$events
		);

		$actions = array();
		if ( null !== $identity ) {
			$actions['registrationPolicy'] = self::postAction(
				'charter_oauth_update_dcr',
				'charter_oauth_update_dcr:' . $issuer
			);
			$actions['registerClient']     = self::postAction(
				'charter_oauth_register_client',
				'charter_oauth_register_client:' . $issuer
			);
			$actions['revokeAll']          = self::postAction(
				'charter_oauth_revoke_all_site_grants',
				'charter_oauth_revoke_all_site_grants:' . hash( 'sha256', $issuer )
			);
			if ( SiteState::PREPARED === $state ) {
				$actions['enable'] = self::postAction(
					'charter_oauth_enable',
					'charter_oauth_enable:' . $issuer,
					array( 'issuer' => $issuer )
				);
			}
		}

		$modeActions = array();
		if ( $enabled ) {
			foreach ( array( EmergencyContainment::RESUMED, EmergencyContainment::ISSUANCE_PAUSED, EmergencyContainment::LOCKDOWN ) as $mode ) {
				$modeActions[ $mode ] = self::postAction(
					self::CONTAINMENT_ACTION,
					self::containmentNonceAction( $issuer, $mode ),
					array( 'mode' => $mode )
				);
			}
		}

		$keyActions = array();
		if ( is_array( $signingKey ) ) {
			$mismatchId = $signingKey['mismatch_id'];
			if ( is_string( $mismatchId ) && self::isBindingId( $mismatchId ) && ! $signingKey['audit_pending'] ) {
				$keyActions['adopt'] = self::postAction(
					self::ADOPT_KEY_ACTION,
					self::signingKeyNonceAction( self::ADOPT_KEY_ACTION, $issuer, $mismatchId ),
					array( 'mismatch_id' => $mismatchId )
				);
			}
			$transitionId = $signingKey['transition_id'];
			if ( $signingKey['audit_pending'] && is_string( $transitionId ) && self::isBindingId( $transitionId ) ) {
				$keyActions['reconcile'] = self::postAction(
					self::KEY_AUDIT_ACTION,
					self::signingKeyNonceAction( self::KEY_AUDIT_ACTION, $issuer, $transitionId ),
					array( 'transition_id' => $transitionId )
				);
			}
		}

		$notices = array();
		if ( 'pending' === self::getScalar( 'containment_audit' ) ) {
			$notices[] = array(
				'status'  => 'warning',
				'message' => __( 'The requested OAuth emergency mode is active, but its audit event is pending reconciliation.', 'charter' ),
			);
		}
		if ( 'adopted' === self::getScalar( 'signing_key' ) ) {
			$notices[] = array(
				'status'  => 'success',
				'message' => __( 'The exact current signing-key replacement was adopted for this issuer.', 'charter' ),
			);
		} elseif ( 'reconciled' === self::getScalar( 'signing_key' ) ) {
			$notices[] = array(
				'status'  => 'success',
				'message' => __( 'The pending signing-key audit event was reconciled.', 'charter' ),
			);
		}

		return array(
			'state'               => $state,
			'enabled'             => $enabled,
			'issuer'              => $issuer,
			'urls'                => null === $urls ? null : array(
				'authorizationServer' => $urls->authorizationServerMetadata(),
				'protectedResource'   => $urls->protectedResourceMetadata(),
			),
			'dynamicRegistration' => DynamicRegistrationService::isEnabled(),
			'clients'             => $clientRows,
			'grants'              => $grantRows,
			'grantCount'          => $grantCount,
			'grantPagination'     => array(
				'page'     => $grantPage,
				'pages'    => $grantPages,
				'previous' => 1 < $grantPage ? add_query_arg( 'grant_page', $grantPage - 1, admin_url( 'options-general.php?page=charter-oauth' ) ) : null,
				'next'     => $grantPage < $grantPages ? add_query_arg( 'grant_page', $grantPage + 1, admin_url( 'options-general.php?page=charter-oauth' ) ) : null,
			),
			'events'              => $eventRows,
			'containment'         => $containment,
			'signingKey'          => $signingKey,
			'actions'             => $actions,
			'modeActions'         => $modeActions,
			'keyActions'          => $keyActions,
			'notices'             => $notices,
		);
	}

	/**
	 * Creates one nonce-bound form description for the component application.
	 *
	 * @param string                $action Fixed admin-post action.
	 * @param string                $nonceAction Exact nonce action.
	 * @param array<string, string> $fields Additional bound fields.
	 * @return array{url:string,fields:array<string,string>}
	 */
	private static function postAction( string $action, string $nonceAction, array $fields = array() ): array {
		return array(
			'url'    => admin_url( 'admin-post.php' ),
			'fields' => array_merge(
				array(
					'action'   => $action,
					'_wpnonce' => wp_create_nonce( $nonceAction ),
				),
				$fields
			),
		);
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

	/** Revokes one exact current-site authorization. */
	public function revokeGrant(): never {
		$this->requireAdministrator();
		$identity = $this->requireIdentity();
		$grantId  = absint( self::postScalar( 'grant_id' ) );
		$action   = 'charter_oauth_revoke_site_grant';
		check_admin_referer( $action . ':' . hash( 'sha256', $identity->issuer() . "\0" . $grantId ) );

		if ( null === $this->grantGovernance->revoke( $identity->issuer(), $grantId, get_current_user_id(), time() ) ) {
			wp_die( esc_html__( 'The OAuth authorization could not be revoked.', 'charter' ), '', array( 'response' => 400 ) );
		}

		wp_safe_redirect( $this->settingsUrl() );
		exit;
	}

	/** Revokes every active authorization inside the current site issuer. */
	public function revokeAllGrants(): never {
		$this->requireAdministrator();
		$identity = $this->requireIdentity();
		$action   = 'charter_oauth_revoke_all_site_grants';
		check_admin_referer( $action . ':' . hash( 'sha256', $identity->issuer() ) );

		if ( '1' !== self::postScalar( 'confirm_revocation' ) || array() === $this->grantGovernance->revokeAll( $identity->issuer(), get_current_user_id(), time() ) ) {
			wp_die( esc_html__( 'The site OAuth authorizations could not be revoked.', 'charter' ), '', array( 'response' => 400 ) );
		}

		wp_safe_redirect( $this->settingsUrl() );
		exit;
	}

	/** Applies one explicitly confirmed exact-issuer emergency transition. */
	public function setContainmentMode(): never {
		$this->requireAdministrator();
		$identity = $this->requireIdentity();
		$mode     = self::postScalar( 'mode' );
		check_admin_referer( self::containmentNonceAction( $identity->issuer(), $mode ) );

		if (
			'1' !== self::postScalar( 'confirm_action' )
			|| ! $this->containment->transition( $mode, EmergencyContainment::ACTOR_SITE_ADMIN, get_current_user_id(), time(), $identity->issuer() )
		) {
			wp_die( esc_html__( 'The OAuth emergency mode could not be changed.', 'charter' ), '', array( 'response' => 400 ) );
		}

		$redirect = $this->settingsUrl();
		if ( $this->containment->snapshot()['audit_pending'] ) {
			$redirect = add_query_arg( 'containment_audit', 'pending', $redirect );
		}
		wp_safe_redirect( $redirect );
		exit;
	}

	/** Adopts one exact current explicit-key mismatch for this issuer. */
	public function adoptSigningKey(): never {
		$this->requireAdministrator();
		$identity   = $this->requireIdentity();
		$mismatchId = self::postScalar( 'mismatch_id' );
		check_admin_referer( self::signingKeyNonceAction( self::ADOPT_KEY_ACTION, $identity->issuer(), $mismatchId ) );

		if (
			'1' !== self::postScalar( 'confirm_action' )
			|| ! self::isBindingId( $mismatchId )
			|| ! $this->signingKeys->adoptReplacement( SigningKeyLifecycle::ACTOR_SITE_ADMIN, get_current_user_id(), time(), $identity->issuer(), $mismatchId )
		) {
			wp_die( esc_html__( 'The explicit Charter key replacement could not be adopted.', 'charter' ), '', array( 'response' => 400 ) );
		}

		$redirect = add_query_arg( 'signing_key', 'adopted', $this->settingsUrl() );
		if ( $this->signingKeys->snapshot()['audit_pending'] ) {
			$redirect = add_query_arg( 'signing_key_audit', 'pending', $redirect );
		}
		wp_safe_redirect( $redirect );
		exit;
	}

	/** Reconciles one exact already-applied key-adoption audit transition. */
	public function reconcileSigningKeyAudit(): never {
		$this->requireAdministrator();
		$identity     = $this->requireIdentity();
		$transitionId = self::postScalar( 'transition_id' );
		check_admin_referer( self::signingKeyNonceAction( self::KEY_AUDIT_ACTION, $identity->issuer(), $transitionId ) );

		if ( ! self::isBindingId( $transitionId ) || ! $this->signingKeys->reconcilePendingAudit( $identity->issuer(), $transitionId ) ) {
			wp_die( esc_html__( 'The explicit-key adoption audit event could not be reconciled.', 'charter' ), '', array( 'response' => 400 ) );
		}

		wp_safe_redirect( add_query_arg( 'signing_key', 'reconciled', $this->settingsUrl() ) );
		exit;
	}

	/** Shows a persistent warning throughout Site Admin while lockdown is active. */
	public function renderLockdownNotice(): void {
		if ( ! current_user_can( 'manage_options' ) || ! $this->siteState->isEnabled() || EmergencyContainment::LOCKDOWN !== $this->containment->mode() ) {
			return;
		}
		?>
		<div class="notice notice-error"><p><?php esc_html_e( 'Charter OAuth lockdown is active: credential issuance and every Charter Bearer request are blocked until an administrator explicitly resumes operation.', 'charter' ); ?></p></div>
		<?php
	}

	/**
	 * Renders the current secret-free key source and exact adoption control.
	 *
	 * @param string $issuer Exact current issuer.
	 */
	private function renderSigningKeyControls( string $issuer ): void {
		$snapshot     = $this->signingKeys->snapshot();
		$mismatchId   = $snapshot['mismatch_id'];
		$transitionId = $snapshot['transition_id'];
		$changedAt    = is_int( $snapshot['changed_at'] ) ? $this->formatTimestamp( $snapshot['changed_at'] ) : __( 'Not applicable', 'charter' );
		$actor        = '' === $snapshot['actor'] ? __( 'Automatic WordPress material', 'charter' ) : $snapshot['actor'];
		?>
		<h2><?php esc_html_e( 'Credential signing key', 'charter' ); ?></h2>
		<p><?php /* translators: 1: Key source, 2: Key status, 3: Explicit generation, 4: Replacement adoption count, 5: Last state time, 6: Last actor. */ echo esc_html( sprintf( __( 'Source: %1$s. Status: %2$s. Generation: %3$d. Explicit replacements adopted: %4$d. Last state change: %5$s. Actor: %6$s.', 'charter' ), $snapshot['source'], $snapshot['status'], $snapshot['generation'], $snapshot['adoption_count'], $changedAt, $actor ) ); ?></p>
		<?php if ( SigningKeyLifecycle::SOURCE_WORDPRESS === $snapshot['source'] ) : ?>
			<p><?php esc_html_e( 'Charter automatically uses the current effective auth, secure_auth, logged_in, and nonce WordPress salt values. A WordPress salt change invalidates prior Charter credentials while new authorization and issuance continue without adoption.', 'charter' ); ?></p>
			<?php if ( $snapshot['database_fallback'] ) : ?>
				<p class="notice notice-warning inline"><?php esc_html_e( 'WordPress is supplying at least part of this material from database-backed fallback state. OAuth remains available.', 'charter' ); ?></p>
			<?php endif; ?>
		<?php elseif ( SigningKeyLifecycle::STATUS_MISMATCH === $snapshot['status'] && $snapshot['audit_pending'] ) : ?>
			<p class="notice notice-error inline"><?php esc_html_e( 'The current explicit key still mismatches this issuer, and the preceding adopted transition has a pending audit event. Credential operations remain blocked; reconcile that exact audit event before adopting another replacement.', 'charter' ); ?></p>
		<?php elseif ( SigningKeyLifecycle::STATUS_MISMATCH === $snapshot['status'] && is_string( $mismatchId ) && self::isBindingId( $mismatchId ) ) : ?>
			<p class="notice notice-error inline"><?php esc_html_e( 'The current CHARTER_SECRET_KEY does not match this issuer’s accepted fingerprint. Credential issuance and Charter credential validation are blocked without changing OAuth state. Restoring the prior value restores operation.', 'charter' ); ?></p>
			<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>">
				<input type="hidden" name="action" value="<?php echo esc_attr( self::ADOPT_KEY_ACTION ); ?>">
				<input type="hidden" name="mismatch_id" value="<?php echo esc_attr( $mismatchId ); ?>">
				<?php wp_nonce_field( self::signingKeyNonceAction( self::ADOPT_KEY_ACTION, $issuer, $mismatchId ) ); ?>
				<label><input type="checkbox" name="confirm_action" value="1" required> <?php esc_html_e( 'I confirm this exact configured replacement for this exact site issuer. Earlier Charter credentials will remain unusable; registrations, consents, grants, and audit history will be preserved.', 'charter' ); ?></label>
				<?php submit_button( __( 'Adopt explicit key replacement', 'charter' ), 'delete', 'submit', false ); ?>
			</form>
		<?php elseif ( in_array( $snapshot['status'], array( SigningKeyLifecycle::STATUS_INVALID, SigningKeyLifecycle::STATUS_UNAVAILABLE, SigningKeyLifecycle::STATUS_UNESTABLISHED ), true ) ) : ?>
			<p class="notice notice-error inline"><?php esc_html_e( 'The explicit Charter signing-key state is unavailable. Credential issuance and Charter credential validation remain blocked.', 'charter' ); ?></p>
		<?php else : ?>
			<p><?php esc_html_e( 'The current explicit CHARTER_SECRET_KEY matches this issuer’s accepted non-secret fingerprint.', 'charter' ); ?></p>
		<?php endif; ?>

		<?php if ( $snapshot['audit_pending'] && is_string( $transitionId ) && self::isBindingId( $transitionId ) ) : ?>
			<p class="notice notice-warning inline"><?php esc_html_e( 'The adopted replacement is active, but its secret-free audit event is pending reconciliation.', 'charter' ); ?></p>
			<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>">
				<input type="hidden" name="action" value="<?php echo esc_attr( self::KEY_AUDIT_ACTION ); ?>">
				<input type="hidden" name="transition_id" value="<?php echo esc_attr( $transitionId ); ?>">
				<?php wp_nonce_field( self::signingKeyNonceAction( self::KEY_AUDIT_ACTION, $issuer, $transitionId ) ); ?>
				<?php submit_button( __( 'Retry key-adoption audit', 'charter' ), 'secondary', 'submit', false ); ?>
			</form>
		<?php endif; ?>
		<p><?php esc_html_e( 'Charter does not back up, export, escrow, recover, overlap, or migrate signing keys or credentials.', 'charter' ); ?></p>
		<?php
	}

	/**
	 * Renders exact current mode and separate reversible emergency actions.
	 *
	 * @param string $issuer Exact current issuer.
	 */
	private function renderContainmentControls( string $issuer ): void {
		$snapshot  = $this->containment->snapshot();
		$changedAt = is_int( $snapshot['changed_at'] ) ? $this->formatTimestamp( $snapshot['changed_at'] ) : __( 'Never changed', 'charter' );
		$actor     = '' === $snapshot['actor'] ? __( 'Default', 'charter' ) : $snapshot['actor'];
		$audit     = $snapshot['audit_pending'] ? __( 'Pending reconciliation', 'charter' ) : __( 'Recorded', 'charter' );
		?>
		<h2><?php esc_html_e( 'Emergency containment', 'charter' ); ?></h2>
		<p><?php /* translators: 1: Current emergency mode, 2: Last mode transition time, 3: Stable actor channel, 4: Audit state. */ echo esc_html( sprintf( __( 'Mode: %1$s. Last change: %2$s. Actor: %3$s. Audit: %4$s.', 'charter' ), $snapshot['mode'], $changedAt, $actor, $audit ) ); ?></p>
		<p><?php esc_html_e( 'Pause issuance keeps existing access tokens usable. Lockdown also rejects every Charter Bearer token. Neither action deletes clients, consents, grants, or credentials, and revocation remains separately available below.', 'charter' ); ?></p>
		<?php
		$this->renderContainmentForm( $issuer, EmergencyContainment::RESUMED, __( 'Resume OAuth', 'charter' ), __( 'Resume registration, authorization, exchange, refresh, and Charter Bearer access.', 'charter' ), 'primary' );
		$this->renderContainmentForm( $issuer, EmergencyContainment::ISSUANCE_PAUSED, __( 'Pause issuance', 'charter' ), __( 'Stop new registrations, authorizations, code exchanges, and refreshes while existing access tokens remain usable.', 'charter' ), 'secondary' );
		$this->renderContainmentForm( $issuer, EmergencyContainment::LOCKDOWN, __( 'Start OAuth lockdown', 'charter' ), __( 'Pause issuance and reject every Charter Bearer token immediately.', 'charter' ), 'delete' );
	}

	/**
	 * Renders one exact-issuer-and-mode-bound confirmation form.
	 *
	 * @param string $issuer Exact current issuer.
	 * @param string $mode Target containment mode.
	 * @param string $label Submit button label.
	 * @param string $confirmation Explicit confirmation statement.
	 * @param string $buttonClass WordPress button class.
	 */
	private function renderContainmentForm( string $issuer, string $mode, string $label, string $confirmation, string $buttonClass ): void {
		?>
		<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>" style="margin: 0 0 1em">
			<input type="hidden" name="action" value="<?php echo esc_attr( self::CONTAINMENT_ACTION ); ?>">
			<input type="hidden" name="mode" value="<?php echo esc_attr( $mode ); ?>">
			<?php wp_nonce_field( self::containmentNonceAction( $issuer, $mode ) ); ?>
			<label><input type="checkbox" name="confirm_action" value="1" required> <?php echo esc_html( $confirmation ); ?></label>
			<?php submit_button( $label, $buttonClass, 'submit', false ); ?>
		</form>
		<?php
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
		$nonce = bin2hex( random_bytes( 16 ) );

		status_header( 200 );
		nocache_headers();
		header( 'Referrer-Policy: no-referrer' );
		header( "Content-Security-Policy: default-src 'none'; style-src 'nonce-" . $nonce . "'; script-src 'nonce-" . $nonce . "'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'" );
		?>
		<!doctype html>
		<html <?php language_attributes(); ?>>
		<head>
			<meta charset="<?php bloginfo( 'charset' ); ?>">
			<meta name="viewport" content="width=device-width, initial-scale=1">
			<title><?php esc_html_e( 'Client registered', 'charter' ); ?></title>
			<style nonce="<?php echo esc_attr( $nonce ); ?>">
				:root { color-scheme: light; font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif; color: #1e1e1e; background: #f0f0f1; }
				* { box-sizing: border-box; }
				body { min-height: 100vh; margin: 0; display: grid; place-items: center; padding: 32px 20px; }
				main { width: min(100%, 620px); background: #fff; border: 1px solid #dcdcde; border-radius: 4px; box-shadow: 0 1px 2px rgba(0, 0, 0, .05); overflow: hidden; }
				.charter-secret__status { display: flex; align-items: center; gap: 10px; margin: 0; padding: 16px 24px; color: #00450c; background: #edfaef; border-bottom: 1px solid #b8e6bf; font-size: 13px; font-weight: 600; }
				.charter-secret__status::before { content: ""; width: 8px; height: 8px; border-radius: 50%; background: #00a32a; box-shadow: 0 0 0 4px rgba(0, 163, 42, .12); }
				.charter-secret__content { padding: 32px; }
				h1 { max-width: 480px; margin: 0 0 12px; font-size: clamp(26px, 5vw, 34px); line-height: 1.15; letter-spacing: -.02em; }
				p { margin: 0 0 16px; color: #50575e; font-size: 15px; line-height: 1.6; }
				.charter-secret__warning { padding-left: 14px; border-left: 3px solid #dba617; color: #3c434a; }
				.charter-secret__field { display: flex; align-items: stretch; gap: 8px; margin: 24px 0 12px; }
				code { min-width: 0; flex: 1; padding: 14px 16px; overflow-wrap: anywhere; color: #1e1e1e; background: #f6f7f7; border: 1px solid #8c8f94; border-radius: 3px; font: 600 14px/1.5 ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; user-select: all; }
				button, a { min-height: 40px; border-radius: 2px; font: 600 13px/1.2 -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif; }
				button { padding: 0 16px; color: #fff; background: #3858e9; border: 1px solid #3858e9; cursor: pointer; }
				button:hover { background: #1d35b4; border-color: #1d35b4; }
				button:focus-visible, a:focus-visible { outline: 2px solid #3858e9; outline-offset: 2px; }
				.charter-secret__feedback { min-height: 20px; margin-bottom: 24px; color: #008a20; font-size: 13px; }
				a { display: inline-flex; align-items: center; color: #3858e9; text-decoration: none; }
				a:hover { text-decoration: underline; }
				@media (max-width: 480px) { .charter-secret__content { padding: 24px; } .charter-secret__field { flex-direction: column; } }
			</style>
		</head>
		<body>
			<main class="charter-secret">
				<p class="charter-secret__status"><?php esc_html_e( 'Confidential client registered', 'charter' ); ?></p>
				<div class="charter-secret__content">
					<h1><?php esc_html_e( 'Save this client secret now', 'charter' ); ?></h1>
					<p><?php /* translators: %s: Client identifier. */ echo esc_html( sprintf( __( 'Confidential client %s was registered.', 'charter' ), $clientId ) ); ?></p>
					<p class="charter-secret__warning"><?php esc_html_e( 'This secret cannot be retrieved after you leave this page.', 'charter' ); ?></p>
					<div class="charter-secret__field">
						<code id="charter-client-secret"><?php echo esc_html( $secret ); ?></code>
						<button type="button" data-charter-copy-secret><?php esc_html_e( 'Copy secret', 'charter' ); ?></button>
					</div>
					<p class="charter-secret__feedback" data-charter-copy-status role="status" aria-live="polite"></p>
					<a href="<?php echo esc_url( $this->settingsUrl() ); ?>"><?php esc_html_e( 'Return to Charter OAuth settings', 'charter' ); ?></a>
				</div>
			</main>
			<script nonce="<?php echo esc_attr( $nonce ); ?>">
				(function () {
					var button = document.querySelector('[data-charter-copy-secret]');
					var secret = document.getElementById('charter-client-secret');
					var status = document.querySelector('[data-charter-copy-status]');
					button.addEventListener('click', function () {
						var text = secret.textContent;
						var copied = function () { status.textContent = <?php echo wp_json_encode( __( 'Secret copied to the clipboard.', 'charter' ) ); ?>; };
						var fallbackCopy = function () {
							var selection = window.getSelection();
							if (!selection) {
								return;
							}
							var range = document.createRange();
							range.selectNodeContents(secret);
							selection.removeAllRanges();
							selection.addRange(range);
							document.execCommand('copy');
							selection.removeAllRanges();
							copied();
						};
						if (navigator.clipboard && window.isSecureContext) {
							navigator.clipboard.writeText(text).then(copied, fallbackCopy);
							return;
						}
						fallbackCopy();
					});
				}());
			</script>
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
	 * Renders one exact issuer-and-grant-bound revocation form.
	 *
	 * @param string $issuer Exact current issuer.
	 * @param int    $grantId Exact grant identifier.
	 */
	private function renderGrantAction( string $issuer, int $grantId ): void {
		$action = 'charter_oauth_revoke_site_grant';
		?>
		<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>">
			<input type="hidden" name="action" value="<?php echo esc_attr( $action ); ?>">
			<input type="hidden" name="grant_id" value="<?php echo esc_attr( (string) $grantId ); ?>">
			<?php wp_nonce_field( $action . ':' . hash( 'sha256', $issuer . "\0" . $grantId ) ); ?>
			<?php submit_button( __( 'Revoke', 'charter' ), 'delete small', 'submit', false ); ?>
		</form>
		<?php
	}

	/**
	 * Returns a safe client display name for one retained grant.
	 *
	 * @param GrantRecord $grant Retained authorization grant.
	 */
	private function clientName( GrantRecord $grant ): string {
		$client = $this->clients->findRegistration( $grant->issuer(), $grant->clientId() );

		return null === $client ? __( 'Unavailable application', 'charter' ) : $client->name();
	}

	/**
	 * Returns one represented-user label without exposing private profile data.
	 *
	 * @param int $userId Represented WordPress user identifier.
	 */
	private function userLabel( int $userId ): string {
		$user = get_userdata( $userId );
		if ( false === $user ) {
			/* translators: %d: WordPress user identifier. */
			return sprintf( __( 'Unavailable user #%d', 'charter' ), $userId );
		}

		/* translators: 1: WordPress display name, 2: WordPress user identifier. */
		return sprintf( __( '%1$s (user #%2$d)', 'charter' ), $user->display_name, $userId );
	}

	/**
	 * Formats an administrator-visible grant timestamp in the site timezone.
	 *
	 * @param int $timestamp Unix timestamp.
	 */
	private function formatTimestamp( int $timestamp ): string {
		$formatted = wp_date( 'Y-m-d H:i:s', $timestamp );

		return is_string( $formatted ) ? $formatted : gmdate( 'Y-m-d H:i:s', $timestamp );
	}

	/**
	 * Renders bounded previous and next authorization inventory links.
	 *
	 * @param int $page Current page.
	 * @param int $pages Total page count.
	 */
	private function renderGrantPagination( int $page, int $pages ): void {
		if ( $pages <= 1 ) {
			return;
		}
		$baseUrl = admin_url( 'options-general.php?page=charter-oauth' );
		?>
		<p class="tablenav-pages">
			<?php
			if ( 1 < $page ) :
				?>
				<a class="button" href="<?php echo esc_url( add_query_arg( 'grant_page', $page - 1, $baseUrl ) ); ?>"><?php esc_html_e( 'Previous authorizations', 'charter' ); ?></a><?php endif; ?>
			<?php /* translators: 1: Current page, 2: Total pages. */ echo esc_html( sprintf( __( 'Page %1$d of %2$d', 'charter' ), $page, $pages ) ); ?>
			<?php
			if ( $page < $pages ) :
				?>
				<a class="button" href="<?php echo esc_url( add_query_arg( 'grant_page', $page + 1, $baseUrl ) ); ?>"><?php esc_html_e( 'Next authorizations', 'charter' ); ?></a><?php endif; ?>
		</p>
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
		$value = $_POST[ $name ] ?? null; // phpcs:ignore WordPress.Security.NonceVerification.Missing,WordPress.Security.ValidatedSanitizedInput.InputNotSanitized,WordPress.Security.ValidatedSanitizedInput.MissingUnslash -- Returned only after explicit unslashing; each owning action validates the bounded value and verifies its nonce.

		return is_string( $value ) ? wp_unslash( $value ) : '';
	}

	/**
	 * Returns the nonce action bound to the exact issuer and target mode.
	 *
	 * @param string $issuer Exact current issuer.
	 * @param string $mode Target containment mode.
	 */
	private static function containmentNonceAction( string $issuer, string $mode ): string {
		return self::CONTAINMENT_ACTION . ':' . hash( 'sha256', $issuer . "\0" . $mode );
	}

	/**
	 * Returns an exact issuer-and-transition-bound signing-key nonce action.
	 *
	 * @param string $action Fixed signing-key action.
	 * @param string $issuer Exact current issuer.
	 * @param string $bindingId Exact mismatch or transition binding.
	 */
	private static function signingKeyNonceAction( string $action, string $issuer, string $bindingId ): string {
		return $action . ':' . hash( 'sha256', $issuer . "\0" . $bindingId );
	}

	/**
	 * Validates one non-secret mismatch or transition binding.
	 *
	 * @param mixed $value Candidate binding.
	 */
	private static function isBindingId( mixed $value ): bool {
		return is_string( $value ) && 1 === preg_match( '/^[a-f0-9]{64}$/D', $value );
	}

	/**
	 * Reads one unslashed scalar query value for presentation-only pagination.
	 *
	 * @param string $name Query field name.
	 */
	private static function getScalar( string $name ): string {
		$value = $_GET[ $name ] ?? null; // phpcs:ignore WordPress.Security.NonceVerification.Recommended,WordPress.Security.ValidatedSanitizedInput.InputNotSanitized,WordPress.Security.ValidatedSanitizedInput.MissingUnslash -- Returned only after explicit unslashing for bounded read-only pagination.

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
