<?php
/**
 * Bounded OAuth client lifecycle cleanup.
 *
 * @package GalatanOvidiu\Charter
 */

declare(strict_types=1);

namespace GalatanOvidiu\Charter\OAuth;

use GalatanOvidiu\Charter\Security\AuditLog;
use GalatanOvidiu\Charter\Site\SiteState;
use Throwable;

/**
 * Runs abandoned-registration cleanup outside credential validation paths.
 *
 * @since 0.1.0
 */
final class ClientCleanup {

	public const HOOK = 'charter_oauth_daily_cleanup';

	/**
	 * Creates bounded site cleanup.
	 *
	 * @param SiteState        $siteState Site lifecycle.
	 * @param ClientRegistry   $clients Client registry.
	 * @param ClientGovernance $governance Client deletion boundary.
	 * @param AuditLog         $audit Security event ledger.
	 */
	public function __construct(
		private readonly SiteState $siteState,
		private readonly ClientRegistry $clients,
		private readonly ClientGovernance $governance,
		private readonly AuditLog $audit
	) {
	}

	/** Registers scheduling and execution hooks. */
	public function registerHooks(): void {
		add_action( 'init', array( $this, 'schedule' ), 20 );
		add_action( self::HOOK, array( $this, 'run' ) );
	}

	/**
	 * Schedules one daily site-scoped cleanup.
	 */
	public function schedule(): void {
		if ( null === $this->siteState->identity() || false !== wp_next_scheduled( self::HOOK ) ) {
			return;
		}
		wp_schedule_event( time() + HOUR_IN_SECONDS, 'daily', self::HOOK );
	}

	/**
	 * Processes no more than one hundred registrations per invocation.
	 */
	public function run(): void {
		$identity = $this->siteState->identity();
		if ( null === $identity ) {
			return;
		}
		$timestamp = time();

		try {
			$candidates = $this->clients->findAbandonedDynamicClients( $identity->issuer(), $timestamp, 100 );
			foreach ( $candidates as $candidate ) {
				$this->governance->deleteAbandoned( $identity->issuer(), $candidate->clientId(), $timestamp );
			}
			update_option( 'charter_oauth_last_cleanup_at', $timestamp, false );
			if ( 100 === count( $candidates ) ) {
				wp_schedule_single_event( $timestamp + MINUTE_IN_SECONDS, self::HOOK );
			}
		} catch ( Throwable ) {
			$this->audit->record( $identity->issuer(), 'cleanup_failed', 'failure', 'dynamic_registration_cleanup', null, null, null, null, $timestamp );
		}
	}
}
