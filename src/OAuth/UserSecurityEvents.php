<?php
/**
 * Deterministic WordPress user security-event handling.
 *
 * @package GalatanOvidiu\Charter
 */

declare(strict_types=1);

namespace GalatanOvidiu\Charter\OAuth;

use GalatanOvidiu\Charter\Site\SiteState;

/**
 * Closes site grants when WordPress invalidates the represented identity.
 *
 * @since 0.1.0
 */
final class UserSecurityEvents {

	/**
	 * Creates the user-event boundary.
	 *
	 * @since 0.1.0
	 *
	 * @param SiteState       $siteState Current-site lifecycle state.
	 * @param CredentialStore $credentials Grant persistence.
	 */
	public function __construct(
		private readonly SiteState $siteState,
		private readonly CredentialStore $credentials
	) {
	}

	/**
	 * Registers the exact deterministic WordPress lifecycle events.
	 *
	 * @since 0.1.0
	 */
	public function registerHooks(): void {
		add_action( 'wp_set_password', array( $this, 'passwordChanged' ), 10, 2 );
		add_action( 'delete_user', array( $this, 'userDeleted' ), 10, 1 );
		add_action( 'remove_user_from_blog', array( $this, 'siteAccessRemoved' ), 10, 2 );
	}

	/**
	 * Revokes the user's grants on every prepared site after any password set.
	 *
	 * @since 0.1.0
	 *
	 * @param mixed $password New plaintext password supplied by WordPress.
	 * @param int   $userId Affected user identifier.
	 */
	public function passwordChanged( mixed $password, int $userId ): void {
		unset( $password );
		if ( ! is_multisite() ) {
			$this->revokeCurrentSite( $userId, 'password_changed' );
			return;
		}

		$sites = get_blogs_of_user( $userId );
		foreach ( $sites as $site ) {
			$value  = $site->userblog_id ?? null;
			$siteId = is_int( $value )
				? $value
				: ( is_string( $value ) && ctype_digit( $value ) ? (int) $value : 0 );
			if ( $siteId <= 0 ) {
				continue;
			}

			switch_to_blog( $siteId );
			try {
				$this->revokeCurrentSite( $userId, 'password_changed' );
			} finally {
				restore_current_blog();
			}
		}
	}

	/**
	 * Revokes current-site grants before a single-site user is deleted.
	 *
	 * @since 0.1.0
	 *
	 * @param int $userId Affected user identifier.
	 */
	public function userDeleted( int $userId ): void {
		$this->revokeCurrentSite( $userId, 'user_deleted' );
	}

	/**
	 * Revokes grants before Multisite removes the user's target-site access.
	 *
	 * WordPress fires this hook while switched into the target blog. The
	 * explicit fallback switch preserves the same boundary for direct hook use.
	 *
	 * @since 0.1.0
	 *
	 * @param int $userId Affected user identifier.
	 * @param int $siteId Target blog identifier.
	 */
	public function siteAccessRemoved( int $userId, int $siteId ): void {
		if ( ! is_multisite() || get_current_blog_id() === $siteId ) {
			$this->revokeCurrentSite( $userId, 'site_access_removed' );
			return;
		}

		switch_to_blog( $siteId );
		try {
			$this->revokeCurrentSite( $userId, 'site_access_removed' );
		} finally {
			restore_current_blog();
		}
	}

	/**
	 * Closes exact current-site grants when that site owns an OAuth identity.
	 *
	 * @param int    $userId Affected user identifier.
	 * @param string $reason Stable deterministic event reason.
	 */
	private function revokeCurrentSite( int $userId, string $reason ): void {
		$identity = $this->siteState->identity();
		if ( null !== $identity ) {
			$this->credentials->revokeAllGrantsForUser( $identity->issuer(), $userId, time(), $reason );
		}
	}
}
