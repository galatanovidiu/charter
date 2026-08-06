<?php
/**
 * Shared site-selection and switched-context operations.
 *
 * @package GalatanOvidiu\Charter
 */

declare(strict_types=1);

namespace GalatanOvidiu\Charter\Site;

use WP_Site;

/**
 * Keeps every cross-site operation inside one live current-network boundary.
 *
 * @since 0.1.0
 */
final class SiteOrchestrator {

	/** Returns WordPress's current non-identity site locator. */
	public static function currentSiteId(): int {
		global $wpdb;

		if ( ! $wpdb instanceof \wpdb ) {
			return 0;
		}

		return is_multisite() ? (int) $wpdb->blogid : 1;
	}

	/**
	 * Reports whether a site is live inside the permitted current-network boundary.
	 *
	 * @param int  $siteId WordPress site identifier.
	 * @param bool $requireNetworkActivation Whether cross-site network authority is mandatory.
	 */
	public static function isOperableSite( int $siteId, bool $requireNetworkActivation = false ): bool {
		if ( $siteId <= 0 ) {
			return false;
		}
		if ( ! is_multisite() ) {
			return ! $requireNetworkActivation && self::currentSiteId() === $siteId;
		}
		if ( ( $requireNetworkActivation || self::currentSiteId() !== $siteId ) && ! NetworkActivation::isActive() ) {
			return false;
		}
		$site = get_site( $siteId );

		return $site instanceof WP_Site
			&& get_current_network_id() === (int) $site->network_id
			&& '1' !== $site->archived
			&& '1' !== $site->spam
			&& '1' !== $site->deleted;
	}

	/**
	 * Returns every live current-network site identifier in stable order.
	 *
	 * @return array<int>
	 */
	public static function liveCurrentNetworkSiteIds(): array {
		if ( ! is_multisite() ) {
			return array();
		}
		$sites = get_sites(
			array(
				'network_id' => get_current_network_id(),
				'number'     => 0,
				'orderby'    => 'id',
				'order'      => 'ASC',
				'archived'   => 0,
				'spam'       => 0,
				'deleted'    => 0,
			)
		);

		return array_map( static fn ( WP_Site $site ): int => (int) $site->blog_id, $sites );
	}

	/**
	 * Runs one operation inside one site's tables, options, and URL context.
	 *
	 * @template T
	 * @param int          $siteId Selected WordPress site identifier.
	 * @param callable():T $operation Site-scoped operation.
	 * @return T
	 */
	public static function withinSite( int $siteId, callable $operation ): mixed {
		$switched = is_multisite();
		if ( $switched ) {
			switch_to_blog( $siteId );
		}
		try {
			return $operation();
		} finally {
			if ( $switched ) {
				restore_current_blog();
			}
		}
	}
}
