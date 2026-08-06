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
	private const NOTICE_CURSOR_OPTION = 'charter_oauth_revocation_notice_cursor';
	private const HISTORY_RETENTION    = 7776000;
	private const NOTICE_REASONS       = array(
		'administrator_grant_revocation',
		'administrator_site_revocation',
		'network_administrator_grant_revocation',
		'network_administrator_site_revocation',
		'administrator_client_block',
		'administrator_client_delete',
		'authorization_code_replay',
		'refresh_token_replay',
	);

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
		add_action( 'admin_notices', array( $this, 'renderRevocationNotice' ) );
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
		$history  = null === $identity
			? array()
			: $this->credentials->listRecentRevokedGrantsForUser( $identity->issuer(), $userId, time() - self::HISTORY_RETENTION );
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

			<?php if ( array() !== $history ) : ?>
				<h2><?php esc_html_e( 'Recently disconnected', 'charter' ); ?></h2>
				<p><?php esc_html_e( 'Charter retains revoked authorization history for up to 90 days so you can understand why access ended.', 'charter' ); ?></p>
				<table class="widefat striped">
					<thead><tr><th><?php esc_html_e( 'Application', 'charter' ); ?></th><th><?php esc_html_e( 'Authorization', 'charter' ); ?></th><th><?php esc_html_e( 'Disconnected', 'charter' ); ?></th></tr></thead>
					<tbody>
					<?php foreach ( $history as $grant ) : ?>
						<tr>
							<td><strong><?php echo esc_html( $this->clientName( $grant ) ); ?></strong><br><code><?php echo esc_html( $grant->clientId() ); ?></code></td>
							<td><?php /* translators: %s: Exact OAuth protected resource URL. */ echo esc_html( sprintf( __( 'Resource: %s', 'charter' ), $grant->resource() ) ); ?><br><?php /* translators: %s: Space-delimited OAuth scope identifiers. */ echo esc_html( sprintf( __( 'Scopes: %s', 'charter' ), $grant->scope() ) ); ?></td>
							<td><?php echo esc_html( $this->revocationReason( $grant->revocationReason() ) ); ?><br><?php echo esc_html( $this->formatTimestamp( $grant->revokedAt() ?? $grant->lastUsedAt() ) ); ?></td>
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
		if (
			null === $identity
			|| ! $this->credentials->revokeGrantForUser( $identity->issuer(), $userId, $grantId, time(), 'user_revocation' )
		) {
			wp_die( esc_html__( 'The OAuth authorization could not be disconnected.', 'charter' ), '', array( 'response' => 400 ) );
		}

		wp_safe_redirect( $this->pageUrl() );
		exit;
	}

	/**
	 * Shows one grouped next-dashboard notice for unseen replay/admin revocation.
	 */
	public function renderRevocationNotice(): void {
		$userId   = get_current_user_id();
		$identity = $this->siteState->identity();
		if ( $userId <= 0 || ! current_user_can( 'read' ) || null === $identity ) {
			return;
		}

		$cursor  = self::noticeCursor( get_user_option( self::NOTICE_CURSOR_OPTION, $userId ) );
		$history = $this->credentials->listRecentRevokedGrantsForUser( $identity->issuer(), $userId, time() - self::HISTORY_RETENTION );
		$unseen  = array_values(
			array_filter(
				$history,
				static fn ( GrantRecord $grant ): bool => self::isAfterCursor( $grant, $cursor ) && in_array( $grant->revocationReason(), self::NOTICE_REASONS, true )
			)
		);
		if ( array() === $unseen ) {
			return;
		}

		$newest = $unseen[0];
		update_user_option(
			$userId,
			self::NOTICE_CURSOR_OPTION,
			array(
				'revoked_at' => $newest->revokedAt(),
				'grant_id'   => $newest->id(),
			)
		);
		?>
		<div class="notice notice-warning is-dismissible"><p>
			<?php echo esc_html( _n( 'One OAuth authorization was revoked for security or by an administrator.', 'Multiple OAuth authorizations were revoked for security or by an administrator.', count( $unseen ), 'charter' ) ); ?>
			<a href="<?php echo esc_url( $this->pageUrl() ); ?>"><?php esc_html_e( 'Review disconnected apps and reasons.', 'charter' ); ?></a>
		</p></div>
		<?php
	}

	/**
	 * Returns a display name without exposing registration secrets.
	 *
	 * @param GrantRecord $grant Authorization grant.
	 */
	private function clientName( GrantRecord $grant ): string {
		$client = $this->clients->findRegistration( $grant->issuer(), $grant->clientId() );

		return null === $client ? __( 'Unavailable application', 'charter' ) : $client->name();
	}

	/**
	 * Returns a stable reason as local user-facing language.
	 *
	 * @param string|null $reason Stable stored revocation reason.
	 */
	private function revocationReason( ?string $reason ): string {
		return match ( $reason ) {
			'user_revocation'                 => __( 'You disconnected this authorization.', 'charter' ),
			'rfc7009_revocation'              => __( 'The application disconnected this authorization.', 'charter' ),
			'administrator_grant_revocation'  => __( 'A site administrator revoked this authorization.', 'charter' ),
			'administrator_site_revocation'   => __( 'A site administrator revoked all site OAuth access.', 'charter' ),
			'network_administrator_grant_revocation' => __( 'A network administrator revoked this authorization for this site.', 'charter' ),
			'network_administrator_site_revocation' => __( 'A network administrator revoked all OAuth access for this site.', 'charter' ),
			'administrator_client_block'      => __( 'A site administrator blocked this application.', 'charter' ),
			'administrator_client_delete'     => __( 'A site administrator deleted this application.', 'charter' ),
			'authorization_code_replay'       => __( 'Charter detected reuse of an authorization code.', 'charter' ),
			'refresh_token_replay'            => __( 'Charter detected reuse of a rotated refresh token.', 'charter' ),
			'password_changed'                => __( 'Your WordPress password changed.', 'charter' ),
			'user_deleted'                    => __( 'The represented WordPress account was deleted.', 'charter' ),
			'site_access_removed'             => __( 'The represented WordPress account lost access to this site.', 'charter' ),
			default                           => __( 'Charter revoked this authorization.', 'charter' ),
		};
	}

	/**
	 * Converts one persisted notification cursor to a safe tuple.
	 *
	 * @param mixed $value Persisted user-option value.
	 * @return array{revoked_at:int,grant_id:int}
	 */
	private static function noticeCursor( mixed $value ): array {
		if ( ! is_array( $value ) ) {
			return array(
				'revoked_at' => 0,
				'grant_id'   => 0,
			);
		}
		$revokedAt = $value['revoked_at'] ?? null;
		$grantId   = $value['grant_id'] ?? null;

		return array(
			'revoked_at' => is_int( $revokedAt ) && 0 <= $revokedAt ? $revokedAt : 0,
			'grant_id'   => is_int( $grantId ) && 0 <= $grantId ? $grantId : 0,
		);
	}

	/**
	 * Reports whether one retained grant sorts after the seen notice cursor.
	 *
	 * @param GrantRecord                        $grant Retained revoked grant.
	 * @param array{revoked_at:int,grant_id:int} $cursor Last displayed notice tuple.
	 */
	private static function isAfterCursor( GrantRecord $grant, array $cursor ): bool {
		$revokedAt = $grant->revokedAt();
		if ( ! is_int( $revokedAt ) ) {
			return false;
		}

		return $revokedAt > $cursor['revoked_at']
			|| ( $revokedAt === $cursor['revoked_at'] && $grant->id() > $cursor['grant_id'] );
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
		$value = $_POST[ $name ] ?? null; // phpcs:ignore WordPress.Security.NonceVerification.Missing,WordPress.Security.ValidatedSanitizedInput.InputNotSanitized,WordPress.Security.ValidatedSanitizedInput.MissingUnslash -- Returned only after explicit unslashing; the owning action validates the bounded identifier and verifies its grant-bound nonce.

		return is_string( $value ) ? wp_unslash( $value ) : '';
	}

	/**
	 * Returns the personal Connected Apps URL.
	 */
	private function pageUrl(): string {
		return admin_url( 'profile.php?page=charter-connected-apps&updated=1' );
	}
}
