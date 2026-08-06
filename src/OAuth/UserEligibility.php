<?php
/**
 * OAuth represented-user eligibility policy.
 *
 * @package GalatanOvidiu\Charter
 */

declare(strict_types=1);

namespace GalatanOvidiu\Charter\OAuth;

/**
 * Keeps authorization, exchange, and token use on one current-site policy.
 *
 * @since 0.1.0
 */
final class UserEligibility {

	/**
	 * Reports whether a WordPress user may currently be represented here.
	 *
	 * @since 0.1.0
	 *
	 * @param int $userId WordPress user identifier.
	 */
	public static function isActiveForCurrentSite( int $userId ): bool {
		if ( false === get_userdata( $userId ) ) {
			return false;
		}

		return ! is_multisite() || is_user_member_of_blog( $userId, get_current_blog_id() );
	}

	/**
	 * This class contains static policy only.
	 */
	private function __construct() {
	}
}
