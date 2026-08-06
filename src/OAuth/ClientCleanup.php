<?php
/**
 * Bounded OAuth retention scheduling and diagnostics.
 *
 * @package GalatanOvidiu\Charter
 */

declare(strict_types=1);

namespace GalatanOvidiu\Charter\OAuth;

use GalatanOvidiu\Charter\Cli\CleanupCommand;
use GalatanOvidiu\Charter\Schema;
use GalatanOvidiu\Charter\Security\AuditLog;
use GalatanOvidiu\Charter\Site\SiteState;
use RuntimeException;
use Throwable;

/**
 * Runs bounded issuer-local maintenance outside credential request paths.
 *
 * @since 0.1.0
 */
final class ClientCleanup {

	public const HOOK = 'charter_oauth_daily_cleanup';

	private const STATUS_OPTION          = 'charter_oauth_cleanup_status';
	private const FIRST_SCHEDULED_OPTION = 'charter_oauth_cleanup_first_scheduled_at';
	private const BATCH_SIZE             = 100;
	private const OVERDUE_AFTER          = 172800;

	/**
	 * Creates bounded site cleanup.
	 *
	 * @param SiteState        $siteState Site lifecycle.
	 * @param RetentionCleanup $retention Retention engine.
	 * @param AuditLog         $audit Security event ledger.
	 */
	public function __construct(
		private readonly SiteState $siteState,
		private readonly RetentionCleanup $retention,
		private readonly AuditLog $audit
	) {
	}

	/** Registers scheduling, execution, diagnostics, and CLI hooks. */
	public function registerHooks(): void {
		add_action( 'init', array( $this, 'schedule' ), 20 );
		add_action( self::HOOK, array( $this, 'run' ), 10, 1 );
		add_filter( 'site_status_tests', array( $this, 'registerSiteHealthTest' ) );

		if ( defined( 'WP_CLI' ) && WP_CLI && class_exists( '\\WP_CLI' ) ) {
			\WP_CLI::add_command( 'charter oauth cleanup', new CleanupCommand( $this, $this->siteState ) );
		}
	}

	/** Schedules one recurring daily job in the current site's own cron option. */
	public function schedule(): void {
		if ( null === $this->siteState->identity() || ! Schema::isInstalled() ) {
			return;
		}
		$timestamp = time();
		$this->recordFirstScheduledAt( $timestamp );
		if ( false !== wp_next_scheduled( self::HOOK ) || false !== wp_next_scheduled( self::HOOK, array( 'daily' ) ) ) {
			return;
		}

		$result = wp_schedule_event( $timestamp + HOUR_IN_SECONDS, 'daily', self::HOOK, array( 'daily' ), true );
		if ( self::schedulingFailed( $result ) ) {
			$this->recordFailure( $timestamp );
			$identity = $this->siteState->identity();
			if ( null !== $identity ) {
				$this->recordAuditFailure( $identity->issuer(), $timestamp, 'cleanup_scheduling' );
			}
		}
	}

	/**
	 * Runs one cron batch and contains failures inside the maintenance boundary.
	 *
	 * @param string $trigger Scheduled trigger label.
	 */
	public function run( string $trigger = 'daily' ): void {
		unset( $trigger );
		try {
			$this->execute( time(), self::BATCH_SIZE, true );
		} catch ( Throwable ) {
			return;
		}
	}

	/**
	 * Executes one observable bounded batch for cron, CLI, or tests.
	 *
	 * @param int  $timestamp Current Unix timestamp.
	 * @param int  $batchSize Maximum records deleted in this batch.
	 * @param bool $scheduleContinuation Whether remaining work schedules cron continuation.
	 * @throws RuntimeException When this site cannot run cleanup or maintenance fails.
	 * @throws Throwable When an underlying cleanup or audit operation fails.
	 */
	public function execute( int $timestamp, int $batchSize = self::BATCH_SIZE, bool $scheduleContinuation = false ): CleanupBatchResult {
		$identity = $this->siteState->identity();
		if ( null === $identity || ! Schema::isInstalled() ) {
			throw new RuntimeException( 'charter_cleanup_site_unavailable' );
		}

		try {
			$result = $this->retention->runBatch( $identity->issuer(), $timestamp, $batchSize );
			if ( $scheduleContinuation && $result->hasMore() ) {
				$this->scheduleContinuation( $timestamp );
			}
			$this->recordSuccess( $timestamp, $result );
			if ( ! $result->hasMore() ) {
				$this->audit->record( $identity->issuer(), 'cleanup_completed', 'success', 'retention_cleanup', null, null, null, null, $timestamp );
			}

			return $result;
		} catch ( Throwable $exception ) {
			$this->recordFailure( $timestamp );
			$this->recordAuditFailure( $identity->issuer(), $timestamp, 'retention_cleanup' );
			throw $exception;
		}
	}

	/**
	 * Returns a validated non-secret operational snapshot.
	 *
	 * @param int|null $timestamp Current time override for deterministic checks.
	 * @return array{state:string,last_run_at:?int,last_completed_at:?int,last_failure_at:?int,failure_reason:?string,first_scheduled_at:?int,last_deleted:array<string,int>}
	 */
	public function statusSnapshot( ?int $timestamp = null ): array {
		$now            = $timestamp ?? time();
		$status         = get_option( self::STATUS_OPTION, array() );
		$status         = is_array( $status ) ? $status : array();
		$lastRun        = self::nullableTimestamp( $status['last_run_at'] ?? null );
		$lastCompleted  = self::nullableTimestamp( $status['last_completed_at'] ?? null );
		$lastFailure    = self::nullableTimestamp( $status['last_failure_at'] ?? null );
		$failureReason  = is_string( $status['failure_reason'] ?? null ) && 1 === preg_match( '/^[a-z0-9_]{1,64}$/D', $status['failure_reason'] ) ? $status['failure_reason'] : null;
		$firstScheduled = self::nullableTimestamp( get_option( self::FIRST_SCHEDULED_OPTION, null ) );
		$lastDeleted    = self::validatedCounts( $status['last_deleted'] ?? null );
		$anchor         = $lastRun ?? $firstScheduled;
		$state          = 'scheduled';
		if ( is_int( $lastFailure ) && ( null === $lastRun || $lastFailure >= $lastRun ) ) {
			$state = 'failed';
		} elseif ( is_int( $anchor ) && $anchor + self::OVERDUE_AFTER < $now ) {
			$state = 'overdue';
		} elseif ( is_int( $lastRun ) ) {
			$state = 'current';
		}

		return array(
			'state'              => $state,
			'last_run_at'        => $lastRun,
			'last_completed_at'  => $lastCompleted,
			'last_failure_at'    => $lastFailure,
			'failure_reason'     => $failureReason,
			'first_scheduled_at' => $firstScheduled,
			'last_deleted'       => $lastDeleted,
		);
	}

	/**
	 * Adds the current-site cleanup diagnostic to Site Health.
	 *
	 * @param array<string, mixed> $tests Registered Site Health tests.
	 * @return array<string, mixed>
	 */
	public function registerSiteHealthTest( array $tests ): array {
		$direct                          = $tests['direct'] ?? array();
		$direct                          = is_array( $direct ) ? $direct : array();
		$direct['charter_oauth_cleanup'] = array(
			'label' => __( 'Charter OAuth retention cleanup', 'charter' ),
			'test'  => array( $this, 'siteHealthResult' ),
		);
		$tests['direct']                 = $direct;

		return $tests;
	}

	/**
	 * Projects truthful current-site maintenance state for Site Health.
	 *
	 * @return array{status:string,label:string,badge:array{label:string,color:string},description:string,test:string}
	 */
	public function siteHealthResult(): array {
		$identity = $this->siteState->identity();
		if ( null === $identity || ! Schema::isInstalled() ) {
			return self::siteHealthProjection(
				'good',
				__( 'Charter OAuth cleanup is not required for this site', 'charter' ),
				__( 'This site has no prepared Charter OAuth issuer or storage to maintain.', 'charter' )
			);
		}

		$status = $this->statusSnapshot();
		if ( 'failed' === $status['state'] ) {
			return self::siteHealthProjection(
				'critical',
				__( 'Charter OAuth cleanup failed', 'charter' ),
				__( 'The last issuer-local retention job failed. Run the Charter OAuth cleanup WP-CLI command after correcting the storage or cron failure.', 'charter' )
			);
		}
		if ( 'overdue' === $status['state'] ) {
			return self::siteHealthProjection(
				'recommended',
				__( 'Charter OAuth cleanup is overdue', 'charter' ),
				__( 'No successful issuer-local retention batch has run in the last two days. Confirm WP-Cron is being invoked or run the Charter OAuth cleanup WP-CLI command.', 'charter' )
			);
		}

		$description = is_int( $status['last_run_at'] )
			? sprintf(
				/* translators: %s: Human-readable time since cleanup. */
				__( 'The last issuer-local retention batch ran %s ago. Credential validity remains enforced during every request independently of cleanup timing.', 'charter' ),
				human_time_diff( $status['last_run_at'], time() )
			)
			: __( 'Daily issuer-local retention cleanup is scheduled. Credential validity remains enforced during every request independently of cleanup timing.', 'charter' );

		return self::siteHealthProjection( 'good', __( 'Charter OAuth cleanup is current', 'charter' ), $description );
	}

	/** Clears current-site operational status during tests or uninstall. */
	public function deleteStatus(): void {
		delete_option( self::STATUS_OPTION );
		delete_option( self::FIRST_SCHEDULED_OPTION );
	}

	/**
	 * Schedules one de-duplicated bounded continuation.
	 *
	 * @param int $timestamp Current Unix timestamp.
	 * @throws RuntimeException When continuation scheduling fails.
	 */
	private function scheduleContinuation( int $timestamp ): void {
		if ( false !== wp_next_scheduled( self::HOOK, array( 'continuation' ) ) ) {
			return;
		}
		$result = wp_schedule_single_event( $timestamp + MINUTE_IN_SECONDS, self::HOOK, array( 'continuation' ), true );
		if ( self::schedulingFailed( $result ) ) {
			throw new RuntimeException( 'charter_cleanup_continuation_failed' );
		}
	}

	/**
	 * Persists one successful batch without credential or request data.
	 *
	 * @param int                $timestamp Current Unix timestamp.
	 * @param CleanupBatchResult $result Bounded result.
	 */
	private function recordSuccess( int $timestamp, CleanupBatchResult $result ): void {
		$current = get_option( self::STATUS_OPTION, array() );
		$current = is_array( $current ) ? $current : array();
		$record  = array(
			'last_run_at'       => $timestamp,
			'last_completed_at' => $result->hasMore() ? self::nullableTimestamp( $current['last_completed_at'] ?? null ) : $timestamp,
			'last_failure_at'   => null,
			'failure_reason'    => null,
			'last_deleted'      => $result->deleted(),
		);
		$this->persistStatus( $record );
	}

	/**
	 * Persists a stable failure code without exception or secret material.
	 *
	 * @param int $timestamp Current Unix timestamp.
	 */
	private function recordFailure( int $timestamp ): void {
		$current = get_option( self::STATUS_OPTION, array() );
		$current = is_array( $current ) ? $current : array();
		$record  = array(
			'last_run_at'       => self::nullableTimestamp( $current['last_run_at'] ?? null ),
			'last_completed_at' => self::nullableTimestamp( $current['last_completed_at'] ?? null ),
			'last_failure_at'   => $timestamp,
			'failure_reason'    => 'cleanup_execution_failed',
			'last_deleted'      => self::validatedCounts( $current['last_deleted'] ?? null ),
		);
		try {
			$this->persistStatus( $record );
		} catch ( RuntimeException ) {
			return;
		}
	}

	/**
	 * Records one stable maintenance failure without masking its status.
	 *
	 * @param string $issuer Exact issuer.
	 * @param int    $timestamp Current Unix timestamp.
	 * @param string $reason Stable maintenance reason.
	 */
	private function recordAuditFailure( string $issuer, int $timestamp, string $reason ): void {
		try {
			$this->audit->record( $issuer, 'cleanup_failed', 'failure', $reason, null, null, null, null, $timestamp );
		} catch ( Throwable $auditFailure ) {
			// Failure status remains the authoritative operator diagnostic.
			unset( $auditFailure );
		}
	}

	/**
	 * Persists the first daily-schedule anchor idempotently.
	 *
	 * @param int $timestamp Current Unix timestamp.
	 */
	private function recordFirstScheduledAt( int $timestamp ): void {
		if ( is_int( self::nullableTimestamp( get_option( self::FIRST_SCHEDULED_OPTION, null ) ) ) ) {
			return;
		}
		if ( ! add_option( self::FIRST_SCHEDULED_OPTION, $timestamp, '', false ) && get_option( self::FIRST_SCHEDULED_OPTION ) !== $timestamp ) {
			$this->recordFailure( $timestamp );
		}
	}

	/**
	 * Persists and confirms the complete bounded status record.
	 *
	 * @param array<string, mixed> $record Complete status record.
	 * @throws RuntimeException When status cannot be persisted.
	 */
	private function persistStatus( array $record ): void {
		if ( update_option( self::STATUS_OPTION, $record, false ) || get_option( self::STATUS_OPTION ) === $record ) {
			return;
		}
		throw new RuntimeException( 'charter_cleanup_status_failed' );
	}

	/**
	 * Returns a WordPress Site Health result.
	 *
	 * @param string $status Result severity.
	 * @param string $label Result label.
	 * @param string $description Result explanation.
	 * @return array{status:string,label:string,badge:array{label:string,color:string},description:string,test:string}
	 */
	private static function siteHealthProjection( string $status, string $label, string $description ): array {
		return array(
			'status'      => $status,
			'label'       => $label,
			'badge'       => array(
				'label' => __( 'Security', 'charter' ),
				'color' => 'blue',
			),
			'description' => '<p>' . esc_html( $description ) . '</p>',
			'test'        => 'charter_oauth_cleanup',
		);
	}

	/**
	 * Converts a stored non-negative timestamp.
	 *
	 * @param mixed $value Stored value.
	 */
	private static function nullableTimestamp( mixed $value ): ?int {
		return is_int( $value ) && 0 <= $value ? $value : ( is_string( $value ) && ctype_digit( $value ) ? (int) $value : null );
	}

	/**
	 * Returns only stable non-negative cleanup counts.
	 *
	 * @param mixed $counts Stored counts.
	 * @return array<string, int>
	 */
	private static function validatedCounts( mixed $counts ): array {
		if ( ! is_array( $counts ) ) {
			return array();
		}
		$validated = array();
		foreach ( $counts as $category => $count ) {
			if ( is_string( $category ) && 1 === preg_match( '/^[a-z_]{1,32}$/D', $category ) && is_int( $count ) && 0 <= $count ) {
				$validated[ $category ] = $count;
			}
		}

		return $validated;
	}

	/**
	 * Recognizes WordPress cron scheduling failures across supported signatures.
	 *
	 * @param mixed $result WordPress scheduling result.
	 */
	private static function schedulingFailed( mixed $result ): bool {
		return false === $result || is_wp_error( $result );
	}
}
