<?php
/**
 * Charter OAuth signing-key lifecycle WP-CLI command.
 *
 * @package GalatanOvidiu\Charter
 */

declare(strict_types=1);

namespace GalatanOvidiu\Charter\Cli;

use GalatanOvidiu\Charter\OAuth\SigningKeyLifecycle;
use GalatanOvidiu\Charter\Site\SiteOrchestrator;
use GalatanOvidiu\Charter\Site\SiteState;
use Throwable;

/**
 * Inspects or adopts explicit keys inside isolated selected site issuers.
 *
 * ## OPTIONS
 *
 * [--status]
 * : Inspect current secret-free key status. This is the default.
 *
 * [--adopt]
 * : Adopt the exact current explicit CHARTER_SECRET_KEY replacement.
 *
 * [--confirm]
 * : Required with --adopt.
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
 * @phpstan-type StatusResult array{state:string,issuer:?string,source:string,status:string,database_fallback:bool,generation:int,adoption_count:int,changed_at:?int,actor:string,actor_user_id:?int,audit_pending:bool,mismatch_id:?string,transition_id:?string}
 * @phpstan-type AdoptionResult array{status:string,generation:int,adoption_count:int,audit_pending:bool,adopted:bool}
 * @phpstan-type CommandError array{error:string}
 */
final class SigningKeyCommand {

	/**
	 * Creates the site-aware signing-key command.
	 *
	 * @param SigningKeyLifecycle $signingKeys Current switched-site key lifecycle.
	 * @param SiteState           $siteState Current switched-site lifecycle.
	 */
	public function __construct(
		private readonly SigningKeyLifecycle $signingKeys,
		private readonly SiteState $siteState
	) {
	}

	/**
	 * Runs status inspection or one explicitly confirmed adoption.
	 *
	 * @param array<string>        $arguments Positional arguments (unused).
	 * @param array<string, mixed> $options Named WP-CLI options.
	 */
	public function __invoke( array $arguments, array $options ): void {
		unset( $arguments );
		$adopt = array_key_exists( 'adopt', $options );
		if ( $adopt && array_key_exists( 'status', $options ) ) {
			\WP_CLI::error( '--status cannot be combined with --adopt.' );
			return;
		}
		if ( $adopt && ! array_key_exists( 'confirm', $options ) ) {
			\WP_CLI::error( 'Explicit replacement adoption requires --confirm.' );
			return;
		}

		$siteIds = SiteTargets::resolve( $options, true );
		if ( ! $adopt ) {
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
				\WP_CLI::error( 'One or more selected Charter OAuth signing-key inspections failed.' );
			}
			\WP_CLI::success( 'Charter OAuth signing-key status inspected.' );
			return;
		}

		$failed  = false;
		$pending = false;
		foreach ( $this->adoptForSites( $siteIds, time() ) as $siteId => $result ) {
			if ( isset( $result['error'] ) ) {
				if ( array_key_exists( 'network', $options ) && array_key_exists( 'all', $options ) && in_array( $result['error'], array( 'issuer_not_enabled', 'replacement_not_required' ), true ) ) {
					\WP_CLI::log( sprintf( 'Site %d: skipped; %s.', $siteId, $result['error'] ) );
					continue;
				}
				$failed = true;
				\WP_CLI::warning( sprintf( 'Site %d: %s', $siteId, $result['error'] ) );
				continue;
			}
			$pending = $pending || $result['audit_pending'];
			\WP_CLI::log( sprintf( 'Site %d: status=%s; adopted=%s; generation=%d; adoptions=%d; audit=%s', $siteId, $result['status'], $result['adopted'] ? 'yes' : 'no', $result['generation'], $result['adoption_count'], $result['audit_pending'] ? 'pending' : 'recorded' ) );
		}
		if ( $failed ) {
			\WP_CLI::error( 'One or more selected Charter OAuth signing-key adoptions failed.' );
		}
		if ( $pending ) {
			\WP_CLI::warning( 'One or more explicit replacements are active, but audit reconciliation is pending.' );
		}
		\WP_CLI::success( 'Charter OAuth signing-key adoption finished.' );
	}

	/**
	 * Inspects selected sites sequentially and restores the original blog.
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
			try {
				$results[ $siteId ] = SiteOrchestrator::withinSite(
					$siteId,
					function (): array {
						$identity = $this->siteState->identity();

						return array_merge(
							$this->signingKeys->snapshot(),
							array(
								'state'  => $this->siteState->state(),
								'issuer' => null === $identity ? null : $identity->issuer(),
							)
						);
					}
				);
			} catch ( Throwable ) {
				$results[ $siteId ] = array( 'error' => 'signing_key_inspection_failed' );
			}
		}

		return $results;
	}

	/**
	 * Adopts selected current mismatches sequentially and restores the blog.
	 *
	 * @param array<int> $siteIds Selected site IDs.
	 * @param int        $timestamp Current Unix timestamp.
	 * @return array<int, AdoptionResult|CommandError>
	 */
	public function adoptForSites( array $siteIds, int $timestamp ): array {
		$results = array();
		foreach ( $siteIds as $siteId ) {
			if ( ! SiteOrchestrator::isOperableSite( $siteId ) ) {
				$results[ $siteId ] = array( 'error' => 'site_not_operable' );
				continue;
			}
			try {
				$results[ $siteId ] = SiteOrchestrator::withinSite(
					$siteId,
					function () use ( $timestamp ): array {
						$identity = $this->siteState->identity();
						if ( null === $identity || ! $this->siteState->isEnabled() ) {
							return array( 'error' => 'issuer_not_enabled' );
						}
						$snapshot = $this->signingKeys->snapshot();
						if ( $snapshot['audit_pending'] && is_string( $snapshot['transition_id'] ) ) {
							$reconciled = $this->signingKeys->reconcilePendingAudit( $identity->issuer(), $snapshot['transition_id'] );
							$after      = $this->signingKeys->snapshot();

							return $reconciled
								? array(
									'status'         => $after['status'],
									'generation'     => $after['generation'],
									'adoption_count' => $after['adoption_count'],
									'audit_pending'  => $after['audit_pending'],
									'adopted'        => false,
								)
								: array( 'error' => 'signing_key_audit_reconciliation_failed' );
						}
						$mismatchId = $snapshot['mismatch_id'];
						if ( is_string( $mismatchId ) && self::isMismatchId( $mismatchId ) ) {
							$adopted = $this->signingKeys->adoptReplacement( SigningKeyLifecycle::ACTOR_WP_CLI, null, $timestamp, $identity->issuer(), $mismatchId );
							$after   = $this->signingKeys->snapshot();

							return $adopted
								? array(
									'status'         => $after['status'],
									'generation'     => $after['generation'],
									'adoption_count' => $after['adoption_count'],
									'audit_pending'  => $after['audit_pending'],
									'adopted'        => true,
								)
								: array( 'error' => 'signing_key_adoption_failed' );
						}

						return array( 'error' => 'replacement_not_required' );
					}
				);
			} catch ( Throwable ) {
				$results[ $siteId ] = array( 'error' => 'signing_key_adoption_failed' );
			}
		}

		return $results;
	}

	/**
	 * Formats one secret-free status line.
	 *
	 * @param int                  $siteId WordPress site identifier.
	 * @param array<string, mixed> $status Validated key status.
	 * @phpstan-param StatusResult $status
	 */
	private static function statusLine( int $siteId, array $status ): string {
		$issuer    = is_string( $status['issuer'] ) ? $status['issuer'] : 'none';
		$changedAt = is_int( $status['changed_at'] ) ? gmdate( 'c', $status['changed_at'] ) : 'never';
		$actor     = '' === $status['actor'] ? 'none' : $status['actor'];
		$audit     = $status['audit_pending'] ? 'pending' : 'recorded';
		$fallback  = SigningKeyLifecycle::SOURCE_WORDPRESS === $status['source']
			? ( $status['database_fallback'] ? 'database' : 'configuration' )
			: 'not_applicable';

		return sprintf( 'Site %d: state=%s; issuer=%s; source=%s; status=%s; wordpress_material=%s; generation=%d; adoptions=%d; changed_at=%s; actor=%s; audit=%s', $siteId, $status['state'], $issuer, $status['source'], $status['status'], $fallback, $status['generation'], $status['adoption_count'], $changedAt, $actor, $audit );
	}

	/**
	 * Validates one non-secret mismatch binding.
	 *
	 * @param mixed $value Candidate binding.
	 */
	private static function isMismatchId( mixed $value ): bool {
		return is_string( $value ) && 1 === preg_match( '/^[a-f0-9]{64}$/D', $value );
	}
}
