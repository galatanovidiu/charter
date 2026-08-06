<?php
/**
 * Charter OAuth retention WP-CLI command.
 *
 * @package GalatanOvidiu\Charter
 */

declare(strict_types=1);

namespace GalatanOvidiu\Charter\Cli;

use GalatanOvidiu\Charter\OAuth\ClientCleanup;
use GalatanOvidiu\Charter\Schema;
use GalatanOvidiu\Charter\Site\NetworkActivation;
use GalatanOvidiu\Charter\Site\SiteState;
use Throwable;
use WP_Site;

/**
 * Runs or inspects bounded cleanup for the current or explicitly selected sites.
 *
 * ## OPTIONS
 *
 * [--status]
 * : Inspect last-run, overdue, and failure state without running cleanup.
 *
 * [--site=<id>]
 * : Run inside one selected site of a network-active installation.
 *
 * [--network]
 * : Enable sequential network orchestration. Requires --sites.
 *
 * [--sites=<ids>]
 * : Comma-separated selected site IDs, limited to 100. Requires --network.
 *
 * [--batch-size=<number>]
 * : Records per issuer-local batch. Default 100; maximum 100.
 *
 * [--max-batches=<number>]
 * : Bounded batches per selected site. Default 10; maximum 100.
 *
 * @since 0.1.0
 *
 * @phpstan-type CommandError array{error:string}
 * @phpstan-type RunResult array{deleted:int,batches:int,has_more:bool,state:string}
 * @phpstan-type StatusResult array{state:string,last_run_at:?int,last_completed_at:?int,last_failure_at:?int,failure_reason:?string,first_scheduled_at:?int,last_deleted:array<string,int>}
 */
final class CleanupCommand {

	/**
	 * Creates the explicit operational command.
	 *
	 * @param ClientCleanup $cleanup Site cleanup coordinator.
	 * @param SiteState     $siteState Switched-site lifecycle.
	 */
	public function __construct(
		private readonly ClientCleanup $cleanup,
		private readonly SiteState $siteState
	) {
	}

	/**
	 * Runs the command.
	 *
	 * @param array<string>        $arguments Positional arguments (unused).
	 * @param array<string, mixed> $options Named WP-CLI options.
	 */
	public function __invoke( array $arguments, array $options ): void {
		unset( $arguments );
		$siteIds    = $this->selectedSiteIds( $options );
		$statusOnly = array_key_exists( 'status', $options );
		$batchSize  = self::boundedOption( $options, 'batch-size', 100 );
		$maxBatches = self::boundedOption( $options, 'max-batches', 10 );

		if ( $statusOnly ) {
			$failed = false;
			foreach ( $this->statusForSites( $siteIds ) as $siteId => $result ) {
				if ( isset( $result['error'] ) ) {
					$failed = true;
					\WP_CLI::warning( sprintf( 'Site %d: %s', $siteId, $result['error'] ) );
					continue;
				}
				\WP_CLI::log( self::statusLine( $siteId, $result ) );
			}
			if ( $failed ) {
				\WP_CLI::error( 'One or more selected Charter OAuth site inspections failed.' );
			}
			\WP_CLI::success( 'Charter OAuth cleanup status inspected.' );
			return;
		}

		$failed = false;
		foreach ( $this->runForSites( $siteIds, $batchSize, $maxBatches ) as $siteId => $result ) {
			if ( isset( $result['error'] ) ) {
				$failed = true;
				\WP_CLI::warning( sprintf( 'Site %d: %s', $siteId, $result['error'] ) );
				continue;
			}
			\WP_CLI::log(
				sprintf(
					'Site %d: deleted %d record(s) in %d batch(es); state=%s%s',
					$siteId,
					$result['deleted'],
					$result['batches'],
					$result['state'],
					$result['has_more'] ? '; eligible records remain' : ''
				)
			);
		}

		if ( $failed ) {
			\WP_CLI::error( 'One or more selected Charter OAuth site jobs failed.' );
		}
		\WP_CLI::success( 'Charter OAuth cleanup finished.' );
	}

	/**
	 * Runs selected sites sequentially, restoring the original blog each time.
	 *
	 * @param array<int> $siteIds Selected sites.
	 * @param int        $batchSize Records per batch.
	 * @param int        $maxBatches Maximum batches per site.
	 * @param int|null   $timestamp Deterministic timestamp override.
	 * @return array<int, RunResult|CommandError>
	 */
	public function runForSites( array $siteIds, int $batchSize = 100, int $maxBatches = 10, ?int $timestamp = null ): array {
		$batchSize  = max( 1, min( 100, $batchSize ) );
		$maxBatches = max( 1, min( 100, $maxBatches ) );
		$results    = array();
		foreach ( $siteIds as $siteId ) {
			if ( ! $this->isOperableSite( $siteId ) ) {
				$results[ $siteId ] = array( 'error' => 'site_not_operable' );
				continue;
			}
			$switched = is_multisite();
			if ( $switched ) {
				switch_to_blog( $siteId );
			}
			try {
				if ( null === $this->siteState->identity() || ! Schema::isInstalled() ) {
					$results[ $siteId ] = array( 'error' => 'issuer_not_prepared' );
					continue;
				}
				$deleted = 0;
				$batches = 0;
				$hasMore = false;
				do {
					$result   = $this->cleanup->execute( $timestamp ?? time(), $batchSize, false );
					$deleted += $result->totalDeleted();
					$hasMore  = $result->hasMore();
					++$batches;
				} while ( $hasMore && $batches < $maxBatches );
				$status             = $this->cleanup->statusSnapshot( $timestamp );
				$results[ $siteId ] = array(
					'deleted'  => $deleted,
					'batches'  => $batches,
					'has_more' => $hasMore,
					'state'    => $status['state'],
				);
			} catch ( Throwable ) {
				$results[ $siteId ] = array( 'error' => 'cleanup_execution_failed' );
			} finally {
				if ( $switched ) {
					restore_current_blog();
				}
			}
		}

		return $results;
	}

	/**
	 * Reads selected-site status sequentially without initializing OAuth state.
	 *
	 * @param array<int> $siteIds Selected sites.
	 * @param int|null   $timestamp Deterministic timestamp override.
	 * @return array<int, StatusResult|CommandError>
	 */
	public function statusForSites( array $siteIds, ?int $timestamp = null ): array {
		$results = array();
		foreach ( $siteIds as $siteId ) {
			if ( ! $this->isOperableSite( $siteId ) ) {
				$results[ $siteId ] = array( 'error' => 'site_not_operable' );
				continue;
			}
			$switched = is_multisite();
			if ( $switched ) {
				switch_to_blog( $siteId );
			}
			try {
				$status = $this->cleanup->statusSnapshot( $timestamp );
				if ( null === $this->siteState->identity() || ! Schema::isInstalled() ) {
					$status['state'] = 'not_configured';
				}
				$results[ $siteId ] = $status;
			} catch ( Throwable ) {
				$results[ $siteId ] = array( 'error' => 'cleanup_status_failed' );
			} finally {
				if ( $switched ) {
					restore_current_blog();
				}
			}
		}

		return $results;
	}

	/**
	 * Resolves current, selected-site, or explicitly selected network jobs.
	 *
	 * @param array<string, mixed> $options Named WP-CLI options.
	 * @return array<int>
	 */
	private function selectedSiteIds( array $options ): array {
		$network = array_key_exists( 'network', $options );
		$site    = $options['site'] ?? null;
		$sites   = $options['sites'] ?? null;
		if ( $network ) {
			if ( null !== $site || ! is_string( $sites ) || '' === trim( $sites ) || ! NetworkActivation::isActive() ) {
				\WP_CLI::error( '--network requires --sites on a network-active installation and cannot be combined with --site.' );
				return array();
			}
			$tokens = array_map( 'trim', explode( ',', $sites ) );
			if ( 100 < count( $tokens ) || array_filter( $tokens, static fn ( string $token ): bool => ! ctype_digit( $token ) || 0 === (int) $token ) ) {
				\WP_CLI::error( '--sites must contain between 1 and 100 positive site IDs.' );
				return array();
			}
			$ids = array_values( array_unique( array_map( 'intval', $tokens ) ) );

			return $ids;
		}
		if ( null !== $sites ) {
			\WP_CLI::error( '--sites requires --network.' );
			return array();
		}
		if ( null !== $site ) {
			if ( ! NetworkActivation::isActive() || ( ! is_string( $site ) && ! is_int( $site ) ) || ! ctype_digit( (string) $site ) || 0 === (int) $site ) {
				\WP_CLI::error( '--site requires one positive site ID on a network-active installation.' );
				return array();
			}

			return array( (int) $site );
		}

		return array( self::currentSiteId() );
	}

	/**
	 * Reports whether a site is a live member of the current network boundary.
	 *
	 * @param int $siteId WordPress site identifier.
	 */
	private function isOperableSite( int $siteId ): bool {
		if ( $siteId <= 0 ) {
			return false;
		}
		if ( ! is_multisite() ) {
			return self::currentSiteId() === $siteId;
		}
		if ( ! NetworkActivation::isActive() && self::currentSiteId() !== $siteId ) {
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
	 * Parses one bounded positive numeric option.
	 *
	 * @param array<string, mixed> $options Named WP-CLI options.
	 * @param string               $name Option name.
	 * @param int                  $defaultValue Default value.
	 */
	private static function boundedOption( array $options, string $name, int $defaultValue ): int {
		$value = $options[ $name ] ?? null;
		if ( null === $value ) {
			return $defaultValue;
		}
		if ( ( ! is_string( $value ) && ! is_int( $value ) ) || ! ctype_digit( (string) $value ) || (int) $value < 1 || (int) $value > 100 ) {
			\WP_CLI::error( sprintf( '--%s must be an integer from 1 through 100.', $name ) );
			return $defaultValue;
		}

		return (int) $value;
	}

	/** Returns WordPress's current non-identity site locator. */
	private static function currentSiteId(): int {
		global $wpdb;

		if ( ! $wpdb instanceof \wpdb ) {
			return 0;
		}
		return $wpdb->blogid;
	}

	/**
	 * Formats status without issuer or credential material.
	 *
	 * @param int                  $siteId WordPress site identifier.
	 * @param array<string, mixed> $status Validated cleanup status.
	 * @phpstan-param StatusResult $status
	 */
	private static function statusLine( int $siteId, array $status ): string {
		$lastRun       = is_int( $status['last_run_at'] ?? null ) ? gmdate( 'c', $status['last_run_at'] ) : 'never';
		$lastFailure   = is_int( $status['last_failure_at'] ?? null ) ? gmdate( 'c', $status['last_failure_at'] ) : 'none';
		$failureReason = is_string( $status['failure_reason'] ?? null ) ? $status['failure_reason'] : 'none';

		return sprintf( 'Site %d: state=%s; last_run=%s; last_failure=%s; failure_reason=%s', $siteId, $status['state'], $lastRun, $lastFailure, $failureReason );
	}
}
