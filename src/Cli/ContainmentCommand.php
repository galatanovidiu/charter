<?php
/**
 * Charter OAuth emergency containment WP-CLI command.
 *
 * @package GalatanOvidiu\Charter
 */

declare(strict_types=1);

namespace GalatanOvidiu\Charter\Cli;

use GalatanOvidiu\Charter\OAuth\EmergencyContainment;
use GalatanOvidiu\Charter\Site\SiteOrchestrator;
use GalatanOvidiu\Charter\Site\SiteState;
use Throwable;

/**
 * Inspects or changes reversible containment for current or selected site issuers.
 *
 * ## OPTIONS
 *
 * [--status]
 * : Inspect current containment state. This is the default when --mode is absent.
 *
 * [--mode=<mode>]
 * : Apply resume, pause, or lockdown.
 *
 * [--confirm]
 * : Required for every mode change.
 *
 * [--site=<id>]
 * : Operate on one site of a network-active installation.
 *
 * [--network]
 * : Operate sequentially on --sites or --all in the current network.
 *
 * [--sites=<ids>]
 * : Comma-separated selected site IDs, limited to 100. Requires --network.
 *
 * [--all]
 * : Operate sequentially on every live site in the current network. Requires --network.
 *
 * @since 0.1.0
 *
 * @phpstan-type StatusResult array{state:string,mode:string,issuer:?string,changed_at:?int,actor:string,actor_user_id:?int,audit_pending:bool}
 * @phpstan-type TransitionResult array{mode:string,changed:bool,audit_pending:bool}
 * @phpstan-type CommandError array{error:string}
 */
final class ContainmentCommand {

	/**
	 * Creates the site-aware containment command.
	 *
	 * @param EmergencyContainment $containment Current switched-site emergency mode.
	 * @param SiteState            $siteState Current switched-site lifecycle.
	 */
	public function __construct(
		private readonly EmergencyContainment $containment,
		private readonly SiteState $siteState
	) {
	}

	/**
	 * Runs status inspection or one explicitly confirmed transition.
	 *
	 * @param array<string>        $arguments Positional arguments (unused).
	 * @param array<string, mixed> $options Named WP-CLI options.
	 */
	public function __invoke( array $arguments, array $options ): void {
		unset( $arguments );
		$modeInput = $options['mode'] ?? null;
		if ( null !== $modeInput && ! is_string( $modeInput ) ) {
			\WP_CLI::error( '--mode must be resume, pause, or lockdown.' );
			return;
		}
		if ( null !== $modeInput && array_key_exists( 'status', $options ) ) {
			\WP_CLI::error( '--status cannot be combined with --mode.' );
			return;
		}

		$siteIds = SiteTargets::resolve( $options, true );
		if ( null === $modeInput ) {
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
				\WP_CLI::error( 'One or more selected Charter OAuth containment inspections failed.' );
			}
			\WP_CLI::success( 'Charter OAuth containment status inspected.' );
			return;
		}

		$mode = self::modeFromInput( $modeInput );
		if ( null === $mode ) {
			\WP_CLI::error( '--mode must be resume, pause, or lockdown.' );
			return;
		}
		if ( ! array_key_exists( 'confirm', $options ) ) {
			\WP_CLI::error( 'Mode changes require --confirm.' );
			return;
		}

		$failed  = false;
		$pending = false;
		foreach ( $this->transitionSites( $siteIds, $mode, time() ) as $siteId => $result ) {
			if ( isset( $result['error'] ) ) {
				if ( array_key_exists( 'network', $options ) && array_key_exists( 'all', $options ) && 'issuer_not_enabled' === $result['error'] ) {
					\WP_CLI::log( sprintf( 'Site %d: skipped; issuer is not enabled.', $siteId ) );
					continue;
				}
				$failed = true;
				\WP_CLI::warning( sprintf( 'Site %d: %s', $siteId, $result['error'] ) );
				continue;
			}
			$pending = $pending || $result['audit_pending'];
			\WP_CLI::log( sprintf( 'Site %d: mode=%s; changed=%s; audit=%s', $siteId, $result['mode'], $result['changed'] ? 'yes' : 'no', $result['audit_pending'] ? 'pending' : 'recorded' ) );
		}
		if ( $failed ) {
			\WP_CLI::error( 'One or more selected Charter OAuth containment transitions failed.' );
		}
		if ( $pending ) {
			\WP_CLI::warning( 'One or more selected Charter OAuth modes are active, but audit reconciliation is pending.' );
		}
		\WP_CLI::success( 'Charter OAuth containment transition finished.' );
	}

	/**
	 * Inspects selected sites sequentially and restores the original blog each time.
	 *
	 * @param array<int> $siteIds Selected site IDs.
	 * @return array<int, StatusResult|CommandError>
	 */
	public function statusForSites( array $siteIds ): array {
		$results = array();
		foreach ( $siteIds as $siteId ) {
			if ( ! SiteOrchestrator::isOperableSite( $siteId ) ) {
				$results[ $siteId ] = array( 'error' => 'site_not_operable' );
				continue;
			}

			$results[ $siteId ] = SiteOrchestrator::withinSite(
				$siteId,
				function (): array {
					$identity = $this->siteState->identity();
					$snapshot = $this->containment->snapshot();

					return array_merge(
						$snapshot,
						array(
							'state'  => $this->siteState->state(),
							'issuer' => null === $identity ? null : $identity->issuer(),
						)
					);
				}
			);
		}

		return $results;
	}

	/**
	 * Changes selected sites sequentially and restores the original blog each time.
	 *
	 * @param array<int> $siteIds Selected site IDs.
	 * @param string     $mode Exact target mode.
	 * @param int        $timestamp Transition timestamp.
	 * @return array<int, TransitionResult|CommandError>
	 */
	public function transitionSites( array $siteIds, string $mode, int $timestamp ): array {
		$results = array();
		foreach ( $siteIds as $siteId ) {
			if ( ! SiteOrchestrator::isOperableSite( $siteId ) ) {
				$results[ $siteId ] = array( 'error' => 'site_not_operable' );
				continue;
			}

			$results[ $siteId ] = SiteOrchestrator::withinSite(
				$siteId,
				function () use ( $mode, $timestamp ): array {
					if ( ! $this->siteState->isEnabled() || null === $this->siteState->identity() ) {
						return array( 'error' => 'issuer_not_enabled' );
					}
					$before = $this->containment->mode();
					try {
						$transitioned = $this->containment->transition( $mode, EmergencyContainment::ACTOR_WP_CLI, null, $timestamp );
					} catch ( Throwable ) {
						$transitioned = false;
					}
					if ( ! $transitioned ) {
						return array( 'error' => 'containment_transition_failed' );
					}

					$snapshot = $this->containment->snapshot();

					return array(
						'mode'          => $snapshot['mode'],
						'changed'       => $before !== $mode,
						'audit_pending' => $snapshot['audit_pending'],
					);
				}
			);
		}

		return $results;
	}

	/**
	 * Maps the public command vocabulary to the persisted mode.
	 *
	 * @param string $mode Public command mode.
	 */
	private static function modeFromInput( string $mode ): ?string {
		return match ( strtolower( $mode ) ) {
			'resume'   => EmergencyContainment::RESUMED,
			'pause'    => EmergencyContainment::ISSUANCE_PAUSED,
			'lockdown' => EmergencyContainment::LOCKDOWN,
			default    => null,
		};
	}

	/**
	 * Formats one secret-free status line.
	 *
	 * @param int                  $siteId WordPress site identifier.
	 * @param array<string, mixed> $status Validated containment status.
	 * @phpstan-param StatusResult $status
	 */
	private static function statusLine( int $siteId, array $status ): string {
		$changedAt = is_int( $status['changed_at'] ) ? gmdate( 'c', $status['changed_at'] ) : 'never';
		$actor     = '' === $status['actor'] ? 'none' : $status['actor'];
		$issuer    = is_string( $status['issuer'] ) ? $status['issuer'] : 'none';
		$audit     = $status['audit_pending'] ? 'pending' : 'recorded';

		return sprintf( 'Site %d: state=%s; mode=%s; issuer=%s; changed_at=%s; actor=%s; audit=%s', $siteId, $status['state'], $status['mode'], $issuer, $changedAt, $actor, $audit );
	}
}
