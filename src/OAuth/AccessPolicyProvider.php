<?php
/**
 * Request-local OAuth access policy provider.
 *
 * @package GalatanOvidiu\Charter
 */

declare(strict_types=1);

namespace GalatanOvidiu\Charter\OAuth;

/**
 * Rebuilds active integration registrations for every security decision.
 *
 * @since 0.1.0
 */
final class AccessPolicyProvider {

	/**
	 * Returns the current exact-issuer access policy.
	 *
	 * Integrations register with the `charter_oauth_register_access` action. The
	 * supplied AccessPolicy rejects malformed, colliding, cross-owner, and
	 * cross-issuer registrations without changing the accepted policy.
	 *
	 * @param string $issuer Exact current issuer.
	 */
	public function forIssuer( string $issuer ): AccessPolicy {
		$policy = new AccessPolicy( $issuer );
		if ( function_exists( 'do_action' ) ) {
			do_action( 'charter_oauth_register_access', $policy, $issuer ); // phpcs:ignore WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedHooknameFound -- Public Charter integration hook.
		}

		return $policy;
	}
}
