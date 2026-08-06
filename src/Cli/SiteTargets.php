<?php
/**
 * Shared WP-CLI site-target parsing.
 *
 * @package GalatanOvidiu\Charter
 */

declare(strict_types=1);

namespace GalatanOvidiu\Charter\Cli;

use GalatanOvidiu\Charter\Site\NetworkActivation;
use GalatanOvidiu\Charter\Site\SiteOrchestrator;

/**
 * Resolves current, selected, or all-network CLI site targets.
 *
 * @since 0.1.0
 */
final class SiteTargets {

	/**
	 * Resolves one command's bounded site target options.
	 *
	 * @param array<string, mixed> $options Named WP-CLI options.
	 * @param bool                 $allowAll Whether --network --all is supported.
	 * @return array<int>
	 */
	public static function resolve( array $options, bool $allowAll ): array {
		$network = array_key_exists( 'network', $options );
		$all     = array_key_exists( 'all', $options );
		$site    = $options['site'] ?? null;
		$sites   = $options['sites'] ?? null;

		if ( $network ) {
			if ( ! NetworkActivation::isActive() || null !== $site ) {
				self::networkOptionsError( $allowAll );
				return array();
			}
			if ( $allowAll && $all && null === $sites ) {
				return SiteOrchestrator::liveCurrentNetworkSiteIds();
			}
			if ( $all || ! is_string( $sites ) || '' === trim( $sites ) ) {
				self::networkOptionsError( $allowAll );
				return array();
			}

			return self::selectedIds( $sites );
		}

		if ( $all || null !== $sites ) {
			\WP_CLI::error( $allowAll ? '--sites and --all require --network.' : '--sites requires --network.' );
			return array();
		}
		if ( null !== $site ) {
			if ( ! NetworkActivation::isActive() || ( ! is_string( $site ) && ! is_int( $site ) ) || ! ctype_digit( (string) $site ) || 0 === (int) $site ) {
				\WP_CLI::error( '--site requires one positive site ID on a network-active installation.' );
				return array();
			}

			return array( (int) $site );
		}

		return array( SiteOrchestrator::currentSiteId() );
	}

	/**
	 * Returns one de-duplicated selection of at most 100 positive IDs.
	 *
	 * @param string $sites Comma-separated site identifiers.
	 * @return array<int>
	 */
	private static function selectedIds( string $sites ): array {
		$tokens = array_map( 'trim', explode( ',', $sites ) );
		if ( 100 < count( $tokens ) || array_filter( $tokens, static fn ( string $token ): bool => ! ctype_digit( $token ) || 0 === (int) $token ) ) {
			\WP_CLI::error( '--sites must contain between 1 and 100 positive site IDs.' );
			return array();
		}

		return array_values( array_unique( array_map( 'intval', $tokens ) ) );
	}

	/**
	 * Reports the command-specific valid network target shape.
	 *
	 * @param bool $allowAll Whether --network --all is supported.
	 */
	private static function networkOptionsError( bool $allowAll ): void {
		\WP_CLI::error(
			$allowAll
				? '--network requires exactly one of --sites or --all on a network-active installation and cannot be combined with --site.'
				: '--network requires --sites on a network-active installation and cannot be combined with --site.'
		);
	}
}
