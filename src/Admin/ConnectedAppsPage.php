<?php
/**
 * Personal OAuth authorization management.
 *
 * @package GalatanOvidiu\Charter
 */

declare(strict_types=1);

namespace GalatanOvidiu\Charter\Admin;

use GalatanOvidiu\Charter\OAuth\ClientRegistry;
use GalatanOvidiu\Charter\OAuth\CredentialStore;
use GalatanOvidiu\Charter\OAuth\GrantRecord;
use GalatanOvidiu\Charter\Site\SiteState;

/**
 * Lets each WordPress user inspect and revoke only their own authorizations.
 *
 * @since 0.1.0
 */
final class ConnectedAppsPage {

	/**
	 * Creates the personal authorization screen.
	 *
	 * @since 0.1.0
	 *
	 * @param SiteState       $siteState Site lifecycle and identity.
	 * @param ClientRegistry  $clients Client registry.
	 * @param CredentialStore $credentials Grant persistence.
	 */
	public function __construct(
		private readonly SiteState $siteState,
		private readonly ClientRegistry $clients,
		private readonly CredentialStore $credentials
	) {
	}

	/**
	 * Registers personal administration hooks.
	 *
	 * @since 0.1.0
	 */
	public function registerHooks(): void {
		add_action( 'admin_menu', array( $this, 'registerPage' ) );
		add_action( 'admin_post_charter_oauth_revoke_personal_grant', array( $this, 'revoke' ) );
	}

	/**
	 * Adds Connected Apps under the current user's Profile menu.
	 *
	 * @since 0.1.0
	 */
	public function registerPage(): void {
		add_submenu_page(
			'profile.php',
			esc_html__( 'Connected Apps', 'charter' ),
			esc_html__( 'Connected Apps', 'charter' ),
			'read',
			'charter-connected-apps',
			array( $this, 'render' )
		);
	}

	/**
	 * Renders only the current user's active site authorizations.
	 *
	 * @since 0.1.0
	 */
	public function render(): void {
		$userId   = $this->requireCurrentUser();
		$identity = $this->siteState->identity();
		$grants   = null === $identity
			? array()
			: $this->credentials->listActiveGrantsForUser( $identity->issuer(), $userId );
		?>
		<div class="wrap">
			<h1><?php esc_html_e( 'Connected Apps', 'charter' ); ?></h1>
			<p><?php esc_html_e( 'These applications can act through OAuth as your WordPress account. Your normal WordPress permissions still apply.', 'charter' ); ?></p>
			<?php if ( array() === $grants ) : ?>
				<p><?php esc_html_e( 'You have no active OAuth authorizations on this site.', 'charter' ); ?></p>
			<?php else : ?>
				<table class="widefat striped">
					<thead><tr><th><?php esc_html_e( 'Application', 'charter' ); ?></th><th><?php esc_html_e( 'Authorization', 'charter' ); ?></th><th><?php esc_html_e( 'Activity', 'charter' ); ?></th><th><?php esc_html_e( 'Action', 'charter' ); ?></th></tr></thead>
					<tbody>
					<?php foreach ( $grants as $grant ) : ?>
						<tr>
							<td><strong><?php echo esc_html( $this->clientName( $grant ) ); ?></strong><br><code><?php echo esc_html( $grant->clientId() ); ?></code></td>
							<td><?php /* translators: %s: Exact OAuth protected resource URL. */ echo esc_html( sprintf( __( 'Resource: %s', 'charter' ), $grant->resource() ) ); ?><br><?php /* translators: %s: Space-delimited OAuth scope identifiers. */ echo esc_html( sprintf( __( 'Scopes: %s', 'charter' ), $grant->scope() ) ); ?><br><?php echo esc_html( $grant->continuingAccess() ? __( 'Continuing access: Yes', 'charter' ) : __( 'Continuing access: No', 'charter' ) ); ?></td>
							<td><?php /* translators: %s: Localized authorization date and time. */ echo esc_html( sprintf( __( 'Authorized: %s', 'charter' ), $this->formatTimestamp( $grant->authorizedAt() ) ) ); ?><br><?php /* translators: %s: Localized last activity date and time. */ echo esc_html( sprintf( __( 'Last activity: %s', 'charter' ), $this->formatTimestamp( $grant->lastUsedAt() ) ) ); ?></td>
							<td>
								<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>">
									<input type="hidden" name="action" value="charter_oauth_revoke_personal_grant">
									<input type="hidden" name="grant_id" value="<?php echo esc_attr( (string) $grant->id() ); ?>">
									<?php wp_nonce_field( 'charter_oauth_revoke_personal_grant:' . $grant->id() ); ?>
									<?php submit_button( __( 'Disconnect', 'charter' ), 'delete small', 'submit', false ); ?>
								</form>
							</td>
						</tr>
					<?php endforeach; ?>
					</tbody>
				</table>
			<?php endif; ?>
		</div>
		<?php
	}

	/**
	 * Revokes one grant only when it belongs to the current site user.
	 *
	 * @since 0.1.0
	 */
	public function revoke(): void {
		$userId  = $this->requireCurrentUser();
		$grantId = absint( self::postScalar( 'grant_id' ) );
		check_admin_referer( 'charter_oauth_revoke_personal_grant:' . $grantId );

		$identity = $this->siteState->identity();
		$grant    = $this->credentials->findGrant( $grantId );
		if (
			null === $identity
			|| null === $grant
			|| $grant->issuer() !== $identity->issuer()
			|| $grant->userId() !== $userId
			|| ! $this->credentials->revokeGrant( $grantId, time(), 'user_revocation' )
		) {
			wp_die( esc_html__( 'The OAuth authorization could not be disconnected.', 'charter' ), '', array( 'response' => 400 ) );
		}

		wp_safe_redirect( $this->pageUrl() );
		exit;
	}

	/**
	 * Returns a display name without exposing registration secrets.
	 *
	 * @param GrantRecord $grant Authorization grant.
	 */
	private function clientName( GrantRecord $grant ): string {
		$client = $this->clients->findActive( $grant->issuer(), $grant->clientId() );

		return null === $client ? __( 'Unavailable application', 'charter' ) : $client->name();
	}

	/**
	 * Requires an authenticated current-site WordPress user.
	 *
	 * @return int Current WordPress user ID.
	 */
	private function requireCurrentUser(): int {
		$userId = get_current_user_id();
		if ( $userId <= 0 || ! current_user_can( 'read' ) ) {
			wp_die( esc_html__( 'You are not allowed to manage connected applications.', 'charter' ), '', array( 'response' => 403 ) );
		}

		return $userId;
	}

	/**
	 * Formats an activity timestamp in the site's configured timezone.
	 *
	 * @param int $timestamp Unix timestamp.
	 */
	private function formatTimestamp( int $timestamp ): string {
		$dateFormat = get_option( 'date_format' );
		$timeFormat = get_option( 'time_format' );
		$dateFormat = is_string( $dateFormat ) && '' !== $dateFormat ? $dateFormat : 'Y-m-d';
		$timeFormat = is_string( $timeFormat ) && '' !== $timeFormat ? $timeFormat : 'H:i:s';
		$formatted  = wp_date( $dateFormat . ' ' . $timeFormat, $timestamp );

		return is_string( $formatted ) ? $formatted : gmdate( 'Y-m-d H:i:s', $timestamp );
	}

	/**
	 * Reads one unslashed scalar POST value.
	 *
	 * @param string $name Field name.
	 */
	private static function postScalar( string $name ): string {
		$value = $_POST[ $name ] ?? null; // phpcs:ignore WordPress.Security.NonceVerification.Missing -- The action verifies its grant-bound nonce immediately after parsing the bounded identifier.

		return is_string( $value ) ? wp_unslash( $value ) : '';
	}

	/**
	 * Returns the personal Connected Apps URL.
	 */
	private function pageUrl(): string {
		return admin_url( 'profile.php?page=charter-connected-apps&updated=1' );
	}
}
