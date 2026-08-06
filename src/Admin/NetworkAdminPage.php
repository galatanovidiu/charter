<?php
/**
 * Multisite Network Admin OAuth control plane.
 *
 * @package GalatanOvidiu\Charter
 */

declare(strict_types=1);

namespace GalatanOvidiu\Charter\Admin;

use GalatanOvidiu\Charter\OAuth\GrantRecord;
use GalatanOvidiu\Charter\OAuth\EmergencyContainment;
use GalatanOvidiu\Charter\Site\NetworkActivation;
use GalatanOvidiu\Charter\Site\SiteState;
use WP_Site;

/**
 * Lets network operators govern selected, isolated site issuers.
 *
 * @since 0.1.0
 */
final class NetworkAdminPage {

	private const PAGE_SLUG          = 'charter-oauth-network';
	private const PREPARE_ACTION     = 'charter_oauth_network_prepare_site';
	private const ENABLE_ACTION      = 'charter_oauth_network_enable_site';
	private const REVOKE_ACTION      = 'charter_oauth_network_revoke_site_grant';
	private const REVOKE_ALL_ACTION  = 'charter_oauth_network_revoke_all_site_grants';
	private const CONTAINMENT_ACTION = 'charter_oauth_network_set_containment';
	private const SITES_PER_PAGE     = 50;
	private const GRANTS_PER_PAGE    = 50;

	/**
	 * Creates the Network Admin screen.
	 *
	 * @param NetworkSiteControl $sites Isolated selected-site operations.
	 */
	public function __construct( private readonly NetworkSiteControl $sites ) {
	}

	/** Registers Network Admin presentation and mutation hooks. */
	public function registerHooks(): void {
		add_action( 'network_admin_menu', array( $this, 'registerPage' ) );
		add_action( 'network_admin_edit_' . self::PREPARE_ACTION, array( $this, 'prepareSite' ) );
		add_action( 'network_admin_edit_' . self::ENABLE_ACTION, array( $this, 'enableSite' ) );
		add_action( 'network_admin_edit_' . self::REVOKE_ACTION, array( $this, 'revokeGrant' ) );
		add_action( 'network_admin_edit_' . self::REVOKE_ALL_ACTION, array( $this, 'revokeAllGrants' ) );
		add_action( 'network_admin_edit_' . self::CONTAINMENT_ACTION, array( $this, 'setContainment' ) );
	}

	/** Adds Charter beneath Network Settings only while network-activated. */
	public function registerPage(): void {
		if ( ! NetworkActivation::isActive() ) {
			return;
		}

		add_submenu_page(
			'settings.php',
			esc_html__( 'Charter OAuth', 'charter' ),
			esc_html__( 'Charter OAuth', 'charter' ),
			'manage_network_options',
			self::PAGE_SLUG,
			array( $this, 'render' )
		);
	}

	/** Renders the bounded site selector and one selected site's exact state. */
	public function render(): void {
		$this->requireNetworkOperator();

		$sitesPage = max( 1, absint( self::getScalar( 'sites_page' ) ) );
		$siteCount = $this->siteCount();
		$sitePages = max( 1, (int) ceil( $siteCount / self::SITES_PER_PAGE ) );
		$sitesPage = min( $sitesPage, $sitePages );
		$siteList  = $this->sitePage( $sitesPage );
		$siteId    = absint( self::getScalar( 'site_id' ) );
		$grantPage = max( 1, absint( self::getScalar( 'grant_page' ) ) );
		$snapshot  = 0 < $siteId ? $this->sites->inspect( $siteId, self::GRANTS_PER_PAGE, ( $grantPage - 1 ) * self::GRANTS_PER_PAGE ) : null;
		if ( null !== $snapshot ) {
			$grantPages  = max( 1, (int) ceil( $snapshot->activeGrantCount() / self::GRANTS_PER_PAGE ) );
			$boundedPage = min( $grantPage, $grantPages );
			if ( $boundedPage !== $grantPage ) {
				$grantPage = $boundedPage;
				$snapshot  = $this->sites->inspect( $siteId, self::GRANTS_PER_PAGE, ( $grantPage - 1 ) * self::GRANTS_PER_PAGE );
			}
		}
		?>
		<div class="wrap">
			<h1><?php esc_html_e( 'Charter OAuth network control', 'charter' ); ?></h1>
			<p><?php esc_html_e( 'Select one site to inspect or govern its own OAuth issuer. This screen does not create network clients, grants, credentials, or an OAuth issuer for the network.', 'charter' ); ?></p>
			<?php $this->renderUpdatedNotice(); ?>
			<?php $this->renderAllContainmentControls(); ?>

			<h2><?php esc_html_e( 'Network sites', 'charter' ); ?></h2>
			<?php if ( array() === $siteList ) : ?>
				<p><?php esc_html_e( 'No operable sites are available in this network.', 'charter' ); ?></p>
			<?php else : ?>
				<table class="widefat striped">
					<thead><tr><th><?php esc_html_e( 'Site', 'charter' ); ?></th><th><?php esc_html_e( 'Domain and path', 'charter' ); ?></th><th><?php esc_html_e( 'Action', 'charter' ); ?></th></tr></thead>
					<tbody>
					<?php foreach ( $siteList as $site ) : ?>
						<tr>
							<td><?php /* translators: %d: WordPress Multisite site identifier. */ echo esc_html( sprintf( __( 'Site #%d', 'charter' ), (int) $site->blog_id ) ); ?></td>
							<td><code><?php echo esc_html( $site->domain . $site->path ); ?></code></td>
							<td><a class="button" href="<?php echo esc_url( $this->settingsUrl( (int) $site->blog_id ) ); ?>"><?php esc_html_e( 'Inspect site', 'charter' ); ?></a></td>
						</tr>
					<?php endforeach; ?>
					</tbody>
				</table>
				<?php $this->renderSitePagination( $sitesPage, $sitePages ); ?>
			<?php endif; ?>

			<?php if ( 0 < $siteId && null === $snapshot ) : ?>
				<div class="notice notice-error"><p><?php esc_html_e( 'The selected site is unavailable, outside this network, or not operable.', 'charter' ); ?></p></div>
			<?php elseif ( null !== $snapshot ) : ?>
				<?php $this->renderSite( $snapshot, $grantPage ); ?>
			<?php endif; ?>
		</div>
		<?php
	}

	/** Applies an explicitly confirmed site-scoped preparation. */
	public function prepareSite(): never {
		$this->requireNetworkOperator();
		$siteId = absint( self::postScalar( 'site_id' ) );
		check_admin_referer( self::nonceAction( self::PREPARE_ACTION, (string) $siteId ) );

		if ( '1' !== self::postScalar( 'confirm_action' ) || ! $this->sites->prepare( $siteId, get_current_user_id(), time() ) ) {
			wp_die( esc_html__( 'The selected site could not be prepared.', 'charter' ), '', array( 'response' => 400 ) );
		}

		$this->redirect( $siteId, 'prepared' );
	}

	/** Applies an exact-issuer enablement after explicit discovery confirmation. */
	public function enableSite(): never {
		$this->requireNetworkOperator();
		$siteId = absint( self::postScalar( 'site_id' ) );
		$issuer = self::postScalar( 'issuer' );
		check_admin_referer( self::nonceAction( self::ENABLE_ACTION, (string) $siteId, $issuer ) );

		if ( '1' !== self::postScalar( 'discovery_verified' ) || ! $this->sites->enable( $siteId, $issuer, get_current_user_id(), time() ) ) {
			wp_die( esc_html__( 'The selected exact issuer could not be enabled.', 'charter' ), '', array( 'response' => 400 ) );
		}

		$this->redirect( $siteId, 'enabled' );
	}

	/** Applies an explicitly confirmed site-and-grant-bound revocation. */
	public function revokeGrant(): never {
		$this->requireNetworkOperator();
		$siteId  = absint( self::postScalar( 'site_id' ) );
		$issuer  = self::postScalar( 'issuer' );
		$grantId = absint( self::postScalar( 'grant_id' ) );
		check_admin_referer( self::nonceAction( self::REVOKE_ACTION, (string) $siteId, $issuer, (string) $grantId ) );

		if ( '1' !== self::postScalar( 'confirm_action' ) || null === $this->sites->revokeGrant( $siteId, $grantId, get_current_user_id(), time() ) ) {
			wp_die( esc_html__( 'The selected site authorization could not be revoked.', 'charter' ), '', array( 'response' => 400 ) );
		}

		$this->redirect( $siteId, 'grant_revoked' );
	}

	/** Applies an explicitly confirmed broad invalidation to one selected site. */
	public function revokeAllGrants(): never {
		$this->requireNetworkOperator();
		$siteId = absint( self::postScalar( 'site_id' ) );
		$issuer = self::postScalar( 'issuer' );
		check_admin_referer( self::nonceAction( self::REVOKE_ALL_ACTION, (string) $siteId, $issuer ) );

		if ( '1' !== self::postScalar( 'confirm_action' ) || array() === $this->sites->revokeAllGrants( $siteId, get_current_user_id(), time() ) ) {
			wp_die( esc_html__( 'The selected site OAuth authorizations could not be revoked.', 'charter' ), '', array( 'response' => 400 ) );
		}

		$this->redirect( $siteId, 'site_revoked' );
	}

	/** Applies one selected-site or all-site reversible containment action. */
	public function setContainment(): never {
		$this->requireNetworkOperator();
		$scope  = self::postScalar( 'scope' );
		$mode   = self::postScalar( 'mode' );
		$siteId = absint( self::postScalar( 'site_id' ) );
		$issuer = self::postScalar( 'issuer' );
		check_admin_referer( self::containmentNonceAction( $scope, $mode, $siteId, $issuer ) );

		if ( '1' !== self::postScalar( 'confirm_action' ) || ! EmergencyContainment::isMode( $mode ) ) {
			wp_die( esc_html__( 'The OAuth emergency containment request is invalid.', 'charter' ), '', array( 'response' => 400 ) );
		}

		if ( 'site' === $scope ) {
			if ( ! $this->sites->transitionContainment( $siteId, $issuer, $mode, get_current_user_id(), time() ) ) {
				wp_die( esc_html__( 'The selected site containment mode could not be changed.', 'charter' ), '', array( 'response' => 400 ) );
			}
			$auditPending = $this->sites->containmentAuditPending( $siteId );
			$updated      = false === $auditPending ? 'containment' : 'containment_pending';
			wp_safe_redirect( $this->settingsUrl( $siteId, array( 'updated' => $updated ) ) );
			exit;
		}

		if ( 'all' !== $scope || 0 !== $siteId || '' !== $issuer ) {
			wp_die( esc_html__( 'The OAuth emergency containment scope is invalid.', 'charter' ), '', array( 'response' => 400 ) );
		}

		$counts = $this->sites->transitionAllContainment( $mode, get_current_user_id(), time() );
		wp_safe_redirect(
			$this->settingsUrl(
				0,
				array(
					'updated'   => 'containment_all',
					'changed'   => $counts['changed'],
					'unchanged' => $counts['unchanged'],
					'skipped'   => $counts['skipped'],
					'pending'   => $counts['pending'],
					'failed'    => $counts['failed'],
				)
			)
		);
		exit;
	}

	/**
	 * Renders one selected site's lifecycle, grants, and own event ledger.
	 *
	 * @param NetworkSiteSnapshot $snapshot Selected-site projection.
	 * @param int                 $grantPage Current grant page.
	 */
	private function renderSite( NetworkSiteSnapshot $snapshot, int $grantPage ): void {
		$identity   = $snapshot->identity();
		$grantPages = max( 1, (int) ceil( $snapshot->activeGrantCount() / self::GRANTS_PER_PAGE ) );
		?>
		<hr>
		<h2><?php /* translators: %d: WordPress Multisite site identifier. */ echo esc_html( sprintf( __( 'Selected site #%d', 'charter' ), $snapshot->siteId() ) ); ?></h2>
		<p><?php /* translators: %s: Current isolated site OAuth lifecycle state. */ echo esc_html( sprintf( __( 'OAuth state: %s', 'charter' ), ucfirst( $snapshot->state() ) ) ); ?></p>
		<p><?php echo esc_html( $snapshot->storageReady() ? __( 'Site-scoped OAuth storage is installed.', 'charter' ) : __( 'Site-scoped OAuth storage has not been initialized.', 'charter' ) ); ?></p>

		<?php if ( null === $identity ) : ?>
			<p><?php esc_html_e( 'No OAuth issuer is prepared for this site.', 'charter' ); ?></p>
			<?php if ( SiteState::AVAILABLE === $snapshot->state() ) : ?>
				<?php $this->renderPrepareForm( $snapshot->siteId() ); ?>
			<?php endif; ?>
		<?php else : ?>
			<p><?php /* translators: %s: Exact selected site issuer and resource. */ echo esc_html( sprintf( __( 'Exact issuer and default resource: %s', 'charter' ), $identity->issuer() ) ); ?></p>
			<p><?php /* translators: 1: Current containment mode, 2: Last transition actor, 3: Audit state. */ echo esc_html( sprintf( __( 'Containment mode: %1$s. Last actor: %2$s. Audit: %3$s.', 'charter' ), $snapshot->containmentMode(), '' === $snapshot->containmentActor() ? __( 'Default', 'charter' ) : $snapshot->containmentActor(), $snapshot->containmentAuditPending() ? __( 'Pending reconciliation', 'charter' ) : __( 'Recorded', 'charter' ) ) ); ?></p>
			<?php if ( SiteState::ENABLED === $snapshot->state() ) : ?>
				<?php $this->renderSelectedContainmentControls( $snapshot->siteId(), $identity->issuer() ); ?>
			<?php endif; ?>
			<?php if ( SiteState::PREPARED === $snapshot->state() ) : ?>
				<?php $this->renderEnableForm( $snapshot->siteId(), $identity->issuer() ); ?>
			<?php endif; ?>

			<h3><?php esc_html_e( 'Active site authorizations', 'charter' ); ?></h3>
			<p><?php /* translators: %d: Number of active grants in the selected site. */ echo esc_html( sprintf( _n( '%d active authorization belongs to this site issuer.', '%d active authorizations belong to this site issuer.', $snapshot->activeGrantCount(), 'charter' ), $snapshot->activeGrantCount() ) ); ?></p>
			<?php if ( array() === $snapshot->activeGrants() ) : ?>
				<p><?php esc_html_e( 'No active OAuth authorizations exist for this site issuer.', 'charter' ); ?></p>
			<?php else : ?>
				<table class="widefat striped">
					<thead><tr><th><?php esc_html_e( 'User', 'charter' ); ?></th><th><?php esc_html_e( 'Client', 'charter' ); ?></th><th><?php esc_html_e( 'Authorization', 'charter' ); ?></th><th><?php esc_html_e( 'Action', 'charter' ); ?></th></tr></thead>
					<tbody>
					<?php foreach ( $snapshot->activeGrants() as $grant ) : ?>
						<tr>
							<td><?php /* translators: %d: Represented WordPress user identifier. */ echo esc_html( sprintf( __( 'User #%d', 'charter' ), $grant->userId() ) ); ?></td>
							<td><code><?php echo esc_html( $grant->clientId() ); ?></code></td>
							<td><?php /* translators: %s: Exact protected resource. */ echo esc_html( sprintf( __( 'Resource: %s', 'charter' ), $grant->resource() ) ); ?><br><?php /* translators: %s: Canonical scope set. */ echo esc_html( sprintf( __( 'Scopes: %s', 'charter' ), $grant->scope() ) ); ?><br><?php echo esc_html( $grant->continuingAccess() ? __( 'Continuing access: Yes', 'charter' ) : __( 'Continuing access: No', 'charter' ) ); ?></td>
							<td><?php $this->renderGrantForm( $snapshot->siteId(), $identity->issuer(), $grant ); ?></td>
						</tr>
					<?php endforeach; ?>
					</tbody>
				</table>
				<?php $this->renderGrantPagination( $snapshot->siteId(), $grantPage, $grantPages ); ?>
				<?php $this->renderRevokeAllForm( $snapshot->siteId(), $identity->issuer() ); ?>
			<?php endif; ?>

			<h3><?php esc_html_e( 'Recent site OAuth events', 'charter' ); ?></h3>
			<?php if ( array() === $snapshot->events() ) : ?>
				<p><?php esc_html_e( 'No security or lifecycle events are recorded in this site ledger.', 'charter' ); ?></p>
			<?php else : ?>
				<table class="widefat striped"><thead><tr><th><?php esc_html_e( 'Time', 'charter' ); ?></th><th><?php esc_html_e( 'Event', 'charter' ); ?></th><th><?php esc_html_e( 'Context', 'charter' ); ?></th><th><?php esc_html_e( 'Outcome', 'charter' ); ?></th></tr></thead><tbody>
				<?php foreach ( $snapshot->events() as $event ) : ?>
					<tr><td><?php echo esc_html( $this->formatTimestamp( $event->occurredAt() ) ); ?></td><td><?php echo esc_html( $event->eventType() ); ?><br><?php echo esc_html( $event->reason() ); ?></td><td><?php /* translators: %s: Event client identifier or dash. */ echo esc_html( sprintf( __( 'Client: %s', 'charter' ), $event->clientId() ?? '—' ) ); ?><br><?php /* translators: %s: Represented user identifier or dash. */ echo esc_html( sprintf( __( 'User: %s', 'charter' ), null === $event->representedUserId() ? '—' : (string) $event->representedUserId() ) ); ?></td><td><?php echo esc_html( $event->outcome() ); ?></td></tr>
				<?php endforeach; ?>
				</tbody></table>
			<?php endif; ?>
		<?php endif; ?>
		<?php
	}

	/** Renders network-wide sequential emergency controls. */
	private function renderAllContainmentControls(): void {
		?>
		<h2><?php esc_html_e( 'Network emergency containment', 'charter' ); ?></h2>
		<p><?php esc_html_e( 'Each action visits every live network site sequentially, changes only enabled site issuers, and restores the original site after every isolated transition.', 'charter' ); ?></p>
		<?php
		$this->renderContainmentForm( 'all', 0, '', EmergencyContainment::RESUMED, __( 'Resume all enabled issuers', 'charter' ), __( 'Resume every enabled site issuer in this network.', 'charter' ), 'primary' );
		$this->renderContainmentForm( 'all', 0, '', EmergencyContainment::ISSUANCE_PAUSED, __( 'Pause issuance on all enabled issuers', 'charter' ), __( 'Pause credential issuance independently on every enabled site issuer.', 'charter' ), 'secondary' );
		$this->renderContainmentForm( 'all', 0, '', EmergencyContainment::LOCKDOWN, __( 'Lock down all enabled issuers', 'charter' ), __( 'Reject Charter Bearer access and pause issuance independently on every enabled site issuer.', 'charter' ), 'delete' );
	}

	/**
	 * Renders emergency controls for one exact selected issuer.
	 *
	 * @param int    $siteId Selected WordPress site identifier.
	 * @param string $issuer Exact selected issuer.
	 */
	private function renderSelectedContainmentControls( int $siteId, string $issuer ): void {
		?>
		<h3><?php esc_html_e( 'Selected-site emergency containment', 'charter' ); ?></h3>
		<p><?php esc_html_e( 'Containment is reversible and never deletes clients, consents, grants, or credentials. Permanent revoke-all remains a separate action below.', 'charter' ); ?></p>
		<?php
		$this->renderContainmentForm( 'site', $siteId, $issuer, EmergencyContainment::RESUMED, __( 'Resume selected issuer', 'charter' ), __( 'Resume issuance and Charter Bearer access for only this exact issuer.', 'charter' ), 'primary' );
		$this->renderContainmentForm( 'site', $siteId, $issuer, EmergencyContainment::ISSUANCE_PAUSED, __( 'Pause selected issuer', 'charter' ), __( 'Pause issuance for only this exact issuer while existing access tokens remain usable.', 'charter' ), 'secondary' );
		$this->renderContainmentForm( 'site', $siteId, $issuer, EmergencyContainment::LOCKDOWN, __( 'Lock down selected issuer', 'charter' ), __( 'Pause issuance and reject Charter Bearer access for only this exact issuer.', 'charter' ), 'delete' );
	}

	/**
	 * Renders one exact scope-and-mode-bound Network Admin action.
	 *
	 * @param string $scope Exact site or all-sites scope.
	 * @param int    $siteId Selected site identifier, or zero for all.
	 * @param string $issuer Exact selected issuer, or empty for all.
	 * @param string $mode Target containment mode.
	 * @param string $label Submit button label.
	 * @param string $confirmation Explicit confirmation statement.
	 * @param string $buttonClass WordPress button class.
	 */
	private function renderContainmentForm( string $scope, int $siteId, string $issuer, string $mode, string $label, string $confirmation, string $buttonClass ): void {
		?>
		<form method="post" action="<?php echo esc_url( $this->actionUrl( self::CONTAINMENT_ACTION ) ); ?>" style="margin: 0 0 1em">
			<input type="hidden" name="scope" value="<?php echo esc_attr( $scope ); ?>">
			<input type="hidden" name="mode" value="<?php echo esc_attr( $mode ); ?>">
			<input type="hidden" name="site_id" value="<?php echo esc_attr( (string) $siteId ); ?>">
			<input type="hidden" name="issuer" value="<?php echo esc_attr( $issuer ); ?>">
			<?php wp_nonce_field( self::containmentNonceAction( $scope, $mode, $siteId, $issuer ) ); ?>
			<label><input type="checkbox" name="confirm_action" value="1" required> <?php echo esc_html( $confirmation ); ?></label>
			<?php submit_button( $label, $buttonClass, 'submit', false ); ?>
		</form>
		<?php
	}

	/**
	 * Renders one explicit site-preparation confirmation.
	 *
	 * @param int $siteId Selected WordPress site identifier.
	 */
	private function renderPrepareForm( int $siteId ): void {
		?>
		<form method="post" action="<?php echo esc_url( $this->actionUrl( self::PREPARE_ACTION ) ); ?>">
			<input type="hidden" name="site_id" value="<?php echo esc_attr( (string) $siteId ); ?>">
			<?php wp_nonce_field( self::nonceAction( self::PREPARE_ACTION, (string) $siteId ) ); ?>
			<label><input type="checkbox" name="confirm_action" value="1" required> <?php esc_html_e( 'Prepare only this site and create only its site-scoped OAuth tables and issuer state.', 'charter' ); ?></label>
			<?php submit_button( __( 'Prepare selected site', 'charter' ), 'primary', 'submit', false ); ?>
		</form>
		<?php
	}

	/**
	 * Renders one exact-issuer discovery confirmation.
	 *
	 * @param int    $siteId Selected WordPress site identifier.
	 * @param string $issuer Exact prepared issuer.
	 */
	private function renderEnableForm( int $siteId, string $issuer ): void {
		?>
		<form method="post" action="<?php echo esc_url( $this->actionUrl( self::ENABLE_ACTION ) ); ?>">
			<input type="hidden" name="site_id" value="<?php echo esc_attr( (string) $siteId ); ?>">
			<input type="hidden" name="issuer" value="<?php echo esc_attr( $issuer ); ?>">
			<?php wp_nonce_field( self::nonceAction( self::ENABLE_ACTION, (string) $siteId, $issuer ) ); ?>
			<label><input type="checkbox" name="discovery_verified" value="1" required> <?php esc_html_e( 'I verified both exact metadata URLs from the intended client environment and want to enable only this issuer.', 'charter' ); ?></label>
			<?php submit_button( __( 'Enable selected site issuer', 'charter' ), 'primary', 'submit', false ); ?>
		</form>
		<?php
	}

	/**
	 * Renders one explicit site-and-grant revocation confirmation.
	 *
	 * @param int         $siteId Selected WordPress site identifier.
	 * @param string      $issuer Exact selected site issuer.
	 * @param GrantRecord $grant Exact selected site grant.
	 */
	private function renderGrantForm( int $siteId, string $issuer, GrantRecord $grant ): void {
		?>
		<form method="post" action="<?php echo esc_url( $this->actionUrl( self::REVOKE_ACTION ) ); ?>">
			<input type="hidden" name="site_id" value="<?php echo esc_attr( (string) $siteId ); ?>">
			<input type="hidden" name="issuer" value="<?php echo esc_attr( $issuer ); ?>">
			<input type="hidden" name="grant_id" value="<?php echo esc_attr( (string) $grant->id() ); ?>">
			<?php wp_nonce_field( self::nonceAction( self::REVOKE_ACTION, (string) $siteId, $issuer, (string) $grant->id() ) ); ?>
			<label><input type="checkbox" name="confirm_action" value="1" required> <?php esc_html_e( 'Revoke this authorization and its descendant credentials.', 'charter' ); ?></label>
			<?php submit_button( __( 'Revoke authorization', 'charter' ), 'delete small', 'submit', false ); ?>
		</form>
		<?php
	}

	/**
	 * Renders the explicit broad-invalidation confirmation for one issuer.
	 *
	 * @param int    $siteId Selected WordPress site identifier.
	 * @param string $issuer Exact selected site issuer.
	 */
	private function renderRevokeAllForm( int $siteId, string $issuer ): void {
		?>
		<h4><?php esc_html_e( 'Revoke all access for this site', 'charter' ); ?></h4>
		<p><?php esc_html_e( 'This permanently closes every active grant and descendant credential in this site table. It does not delete site client registrations or affect any sibling site.', 'charter' ); ?></p>
		<form method="post" action="<?php echo esc_url( $this->actionUrl( self::REVOKE_ALL_ACTION ) ); ?>">
			<input type="hidden" name="site_id" value="<?php echo esc_attr( (string) $siteId ); ?>">
			<input type="hidden" name="issuer" value="<?php echo esc_attr( $issuer ); ?>">
			<?php wp_nonce_field( self::nonceAction( self::REVOKE_ALL_ACTION, (string) $siteId, $issuer ) ); ?>
			<label><input type="checkbox" name="confirm_action" value="1" required> <?php esc_html_e( 'I understand that every active OAuth authorization for this selected site will be revoked.', 'charter' ); ?></label>
			<?php submit_button( __( 'Revoke all selected-site grants', 'charter' ), 'delete', 'submit', false ); ?>
		</form>
		<?php
	}

	/** Enforces network activation and the network settings capability. */
	private function requireNetworkOperator(): void {
		if ( ! NetworkActivation::isActive() || ! current_user_can( 'manage_network_options' ) ) {
			wp_die( esc_html__( 'You are not allowed to manage Charter OAuth for this network.', 'charter' ), '', array( 'response' => 403 ) );
		}
	}

	/**
	 * Returns a bounded page of active sites in the current network.
	 *
	 * @param int $page Current site page.
	 * @return array<WP_Site>
	 */
	private function sitePage( int $page ): array {
		return get_sites(
			array(
				'network_id' => get_current_network_id(),
				'number'     => self::SITES_PER_PAGE,
				'offset'     => ( $page - 1 ) * self::SITES_PER_PAGE,
				'orderby'    => 'id',
				'order'      => 'ASC',
				'archived'   => 0,
				'spam'       => 0,
				'deleted'    => 0,
			)
		);
	}

	/** Returns the number of operable sites in the current network. */
	private function siteCount(): int {
		$count = get_sites(
			array(
				'network_id' => get_current_network_id(),
				'count'      => true,
				'archived'   => 0,
				'spam'       => 0,
				'deleted'    => 0,
			)
		);

		return max( 0, $count );
	}

	/**
	 * Renders network-site pagination.
	 *
	 * @param int $page Current page.
	 * @param int $pages Total pages.
	 */
	private function renderSitePagination( int $page, int $pages ): void {
		if ( $pages <= 1 ) {
			return;
		}
		?>
		<p class="tablenav-pages">
			<?php
			if ( 1 < $page ) :
				?>
				<a class="button" href="<?php echo esc_url( $this->settingsUrl( 0, array( 'sites_page' => $page - 1 ) ) ); ?>"><?php esc_html_e( 'Previous sites', 'charter' ); ?></a><?php endif; ?>
			<?php /* translators: 1: Current page, 2: Total pages. */ echo esc_html( sprintf( __( 'Page %1$d of %2$d', 'charter' ), $page, $pages ) ); ?>
			<?php
			if ( $page < $pages ) :
				?>
				<a class="button" href="<?php echo esc_url( $this->settingsUrl( 0, array( 'sites_page' => $page + 1 ) ) ); ?>"><?php esc_html_e( 'Next sites', 'charter' ); ?></a><?php endif; ?>
		</p>
		<?php
	}

	/**
	 * Renders selected-site grant pagination.
	 *
	 * @param int $siteId Selected WordPress site identifier.
	 * @param int $page Current page.
	 * @param int $pages Total pages.
	 */
	private function renderGrantPagination( int $siteId, int $page, int $pages ): void {
		if ( $pages <= 1 ) {
			return;
		}
		?>
		<p class="tablenav-pages">
			<?php
			if ( 1 < $page ) :
				?>
				<a class="button" href="<?php echo esc_url( $this->settingsUrl( $siteId, array( 'grant_page' => $page - 1 ) ) ); ?>"><?php esc_html_e( 'Previous authorizations', 'charter' ); ?></a><?php endif; ?>
			<?php /* translators: 1: Current page, 2: Total pages. */ echo esc_html( sprintf( __( 'Page %1$d of %2$d', 'charter' ), $page, $pages ) ); ?>
			<?php
			if ( $page < $pages ) :
				?>
				<a class="button" href="<?php echo esc_url( $this->settingsUrl( $siteId, array( 'grant_page' => $page + 1 ) ) ); ?>"><?php esc_html_e( 'Next authorizations', 'charter' ); ?></a><?php endif; ?>
		</p>
		<?php
	}

	/** Renders a whitelisted post-action result notice. */
	private function renderUpdatedNotice(): void {
		$updated = self::getScalar( 'updated' );
		$message = match ( $updated ) {
			'prepared'     => __( 'The selected site was prepared inside its own OAuth boundary.', 'charter' ),
			'enabled'      => __( 'The selected site issuer was enabled.', 'charter' ),
			'grant_revoked' => __( 'The selected site authorization was revoked.', 'charter' ),
			'site_revoked' => __( 'All active OAuth grants for the selected site were revoked.', 'charter' ),
			'containment'   => __( 'The selected site containment mode was changed.', 'charter' ),
			'containment_pending' => __( 'The selected site containment mode is active, but its audit record is pending reconciliation.', 'charter' ),
			'containment_all' => sprintf(
				/* translators: 1: Changed sites, 2: Unchanged sites, 3: Skipped sites, 4: Audit-pending sites, 5: Failed sites. */
				__( 'Network containment finished sequentially: %1$d changed, %2$d already in that mode, %3$d without an enabled issuer skipped, %4$d active with audit pending, %5$d failed.', 'charter' ),
				absint( self::getScalar( 'changed' ) ),
				absint( self::getScalar( 'unchanged' ) ),
				absint( self::getScalar( 'skipped' ) ),
				absint( self::getScalar( 'pending' ) ),
				absint( self::getScalar( 'failed' ) )
			),
			default         => '',
		};
		if ( '' !== $message ) {
			$noticeClass = in_array( $updated, array( 'containment_pending', 'containment_all' ), true )
				&& ( 'containment_pending' === $updated || 0 < absint( self::getScalar( 'pending' ) ) || 0 < absint( self::getScalar( 'failed' ) ) )
				? 'notice-warning'
				: 'notice-success';
			?>
			<div class="notice <?php echo esc_attr( $noticeClass ); ?> is-dismissible"><p><?php echo esc_html( $message ); ?></p></div>
			<?php
		}
	}

	/**
	 * Returns one Network Admin edit action URL.
	 *
	 * @param string $action Fixed Network Admin edit action.
	 */
	private function actionUrl( string $action ): string {
		return network_admin_url( 'edit.php?action=' . rawurlencode( $action ) );
	}

	/**
	 * Returns the Network Admin page URL with bounded query arguments.
	 *
	 * @param int                       $siteId Selected site identifier, when present.
	 * @param array<string, int|string> $arguments Additional query arguments.
	 */
	private function settingsUrl( int $siteId = 0, array $arguments = array() ): string {
		$query = array( 'page' => self::PAGE_SLUG );
		if ( 0 < $siteId ) {
			$query['site_id'] = $siteId;
		}

		return add_query_arg( array_merge( $query, $arguments ), network_admin_url( 'settings.php' ) );
	}

	/**
	 * Redirects after one successful mutation.
	 *
	 * @param int    $siteId Selected WordPress site identifier.
	 * @param string $updated Stable result code.
	 */
	private function redirect( int $siteId, string $updated ): never {
		wp_safe_redirect( $this->settingsUrl( $siteId, array( 'updated' => $updated ) ) );
		exit;
	}

	/**
	 * Returns an action nonce bound to every exact selected identifier.
	 *
	 * @param string $action Fixed Network Admin action.
	 * @param string ...$bindings Exact site-scoped bindings.
	 */
	private static function nonceAction( string $action, string ...$bindings ): string {
		return $action . ':' . hash( 'sha256', implode( "\0", $bindings ) );
	}

	/**
	 * Returns an action nonce bound to network, scope, site, issuer, and mode.
	 *
	 * @param string $scope Exact site or all-sites scope.
	 * @param string $mode Target containment mode.
	 * @param int    $siteId Selected site identifier, or zero for all.
	 * @param string $issuer Exact selected issuer, or empty for all.
	 */
	private static function containmentNonceAction( string $scope, string $mode, int $siteId, string $issuer ): string {
		return self::nonceAction( self::CONTAINMENT_ACTION, (string) get_current_network_id(), $scope, (string) $siteId, $issuer, $mode );
	}

	/**
	 * Reads one unslashed scalar POST value.
	 *
	 * @param string $name Field name.
	 */
	private static function postScalar( string $name ): string {
		$value = $_POST[ $name ] ?? null; // phpcs:ignore WordPress.Security.NonceVerification.Missing -- Only bounded identifiers needed to derive the exact action nonce are read before verification.

		return is_string( $value ) ? wp_unslash( $value ) : '';
	}

	/**
	 * Reads one unslashed presentation-only query value.
	 *
	 * @param string $name Field name.
	 */
	private static function getScalar( string $name ): string {
		$value = $_GET[ $name ] ?? null; // phpcs:ignore WordPress.Security.NonceVerification.Recommended -- Read-only site selection and pagination cannot mutate state.

		return is_string( $value ) ? wp_unslash( $value ) : '';
	}

	/**
	 * Formats one event timestamp in the network dashboard timezone.
	 *
	 * @param int $timestamp Unix timestamp.
	 */
	private function formatTimestamp( int $timestamp ): string {
		$formatted = wp_date( 'Y-m-d H:i:s', $timestamp );

		return is_string( $formatted ) ? $formatted : gmdate( 'Y-m-d H:i:s', $timestamp );
	}
}
