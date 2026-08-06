<?php
/**
 * Reversible issuer-local OAuth emergency containment.
 *
 * @package GalatanOvidiu\Charter
 */

declare(strict_types=1);

namespace GalatanOvidiu\Charter\OAuth;

use GalatanOvidiu\Charter\Cli\ContainmentCommand;
use GalatanOvidiu\Charter\Security\AuditWriter;
use GalatanOvidiu\Charter\Site\SiteState;
use RuntimeException;

/**
 * Owns the current issuer's reversible issuance and bearer-access gates.
 *
 * @since 0.1.0
 *
 * @phpstan-type ContainmentSnapshot array{mode:string,changed_at:?int,actor:string,actor_user_id:?int,audit_pending:bool}
 */
final class EmergencyContainment {

	public const RESUMED         = 'resumed';
	public const ISSUANCE_PAUSED = 'issuance_paused';
	public const LOCKDOWN        = 'lockdown';

	public const ACTOR_SITE_ADMIN    = 'site_administrator';
	public const ACTOR_NETWORK_ADMIN = 'network_administrator';
	public const ACTOR_WP_CLI        = 'wp_cli';

	private const OPTION = 'charter_oauth_emergency_mode';

	/**
	 * Creates the issuer-local containment boundary.
	 *
	 * @param SiteState   $siteState Site lifecycle and identity.
	 * @param AuditWriter $audit Secret-free site event ledger.
	 */
	public function __construct(
		private readonly SiteState $siteState,
		private readonly AuditWriter $audit
	) {
	}

	/** Registers Site Health and WP-CLI operational surfaces. */
	public function registerHooks(): void {
		add_filter( 'site_status_tests', array( $this, 'registerSiteHealthTest' ) );

		if ( defined( 'WP_CLI' ) && WP_CLI && class_exists( '\\WP_CLI' ) ) {
			\WP_CLI::add_command( 'charter oauth containment', new ContainmentCommand( $this, $this->siteState ) );
		}
	}

	/** Returns the validated current issuer mode. */
	public function mode(): string {
		return $this->snapshot()['mode'];
	}

	/** Reports whether DCR, authorization, code exchange, and refresh may issue. */
	public function issuanceAllowed(): bool {
		return self::RESUMED === $this->mode();
	}

	/** Reports whether existing Charter access tokens may authenticate. */
	public function bearerAllowed(): bool {
		return self::LOCKDOWN !== $this->mode();
	}

	/**
	 * Returns stable secret-free operational status.
	 *
	 * @phpstan-return ContainmentSnapshot
	 */
	public function snapshot(): array {
		$stored = get_option( self::OPTION, array() );
		$stored = is_array( $stored ) ? $stored : array();
		$mode   = self::validatedMode( $stored['mode'] ?? null );
		$actor  = self::validatedActor( $stored['actor'] ?? null );

		return array(
			'mode'          => $mode,
			'changed_at'    => self::nullablePositiveInteger( $stored['changed_at'] ?? null ),
			'actor'         => $actor,
			'actor_user_id' => self::nullablePositiveInteger( $stored['actor_user_id'] ?? null ),
			'audit_pending' => true === ( $stored['audit_pending'] ?? false ),
		);
	}

	/**
	 * Applies one exact current-issuer transition without touching OAuth state.
	 *
	 * @param string      $mode Target mode.
	 * @param string      $actor Stable operator channel.
	 * @param int|null    $actorUserId WordPress operator identity, when applicable.
	 * @param int         $timestamp Current Unix timestamp.
	 * @param string|null $expectedIssuer Exact externally bound issuer, when supplied.
	 */
	public function transition( string $mode, string $actor, ?int $actorUserId, int $timestamp, ?string $expectedIssuer = null ): bool {
		$identity = $this->siteState->identity();
		if (
			null === $identity
			|| ! $this->siteState->isEnabled()
			|| ! self::isMode( $mode )
			|| ! self::isActor( $actor )
			|| $timestamp <= 0
			|| ( self::ACTOR_WP_CLI !== $actor && ( null === $actorUserId || $actorUserId <= 0 ) )
			|| ( null !== $expectedIssuer && ! hash_equals( $identity->issuer(), $expectedIssuer ) )
		) {
			return false;
		}

		$current = $this->snapshot();
		if ( $current['mode'] === $mode && ! $current['audit_pending'] ) {
			return true;
		}

		if ( $current['mode'] === $mode && null !== $current['changed_at'] && '' !== $current['actor'] ) {
			$record = $current;
		} else {
			$lastChangedAt = $current['changed_at'] ?? 0;

			$record = array(
				'mode'          => $mode,
				'changed_at'    => max( $timestamp, $lastChangedAt + 1 ),
				'actor'         => $actor,
				'actor_user_id' => $actorUserId,
				'audit_pending' => true,
			);
			if ( ! self::persist( $record ) ) {
				return false;
			}
		}

		$this->reconcileAudit( $identity->issuer(), $record );

		return true;
	}

	/**
	 * Reconciles one applied transition with its exact durable audit event.
	 *
	 * @param string               $issuer Exact current issuer.
	 * @param array<string, mixed> $record Applied transition record.
	 * @phpstan-param ContainmentSnapshot $record
	 */
	private function reconcileAudit( string $issuer, array $record ): bool {
		$timestamp = $record['changed_at'];
		if ( ! is_int( $timestamp ) || '' === $record['actor'] ) {
			return false;
		}
		$reason = $record['actor'] . '_' . $record['mode'];
		try {
			if ( ! $this->audit->hasEvent( $issuer, $timestamp, 'emergency_mode_changed', 'success', $reason, $record['actor_user_id'] ) ) {
				$this->audit->record(
					$issuer,
					'emergency_mode_changed',
					'success',
					$reason,
					$record['actor_user_id'],
					null,
					null,
					null,
					$timestamp
				);
			}
		} catch ( RuntimeException ) {
			return false;
		}
		$record['audit_pending'] = false;

		return self::persist( $record );
	}

	/**
	 * Adds the current issuer's emergency state to Site Health.
	 *
	 * @param array<string, mixed> $tests Registered Site Health tests.
	 * @return array<string, mixed>
	 */
	public function registerSiteHealthTest( array $tests ): array {
		$direct                              = $tests['direct'] ?? array();
		$direct                              = is_array( $direct ) ? $direct : array();
		$direct['charter_oauth_containment'] = array(
			'label' => __( 'Charter OAuth emergency containment', 'charter' ),
			'test'  => array( $this, 'siteHealthResult' ),
		);
		$tests['direct']                     = $direct;

		return $tests;
	}

	/**
	 * Projects the current non-secret containment status for Site Health.
	 *
	 * @return array{status:string,label:string,badge:array{label:string,color:string},description:string,test:string}
	 */
	public function siteHealthResult(): array {
		if ( null === $this->siteState->identity() || ! $this->siteState->isEnabled() ) {
			return self::siteHealthProjection(
				'good',
				__( 'Charter OAuth containment is not active', 'charter' ),
				__( 'This site has no enabled Charter OAuth issuer requiring emergency containment.', 'charter' )
			);
		}

		$snapshot = $this->snapshot();
		if ( $snapshot['audit_pending'] ) {
			return self::siteHealthProjection(
				'critical',
				__( 'Charter OAuth containment audit is incomplete', 'charter' ),
				__( 'The displayed emergency mode is active, but its audit event is not confirmed. Retry the same mode to reconcile the issuer ledger.', 'charter' )
			);
		}

		return match ( $snapshot['mode'] ) {
			self::LOCKDOWN => self::siteHealthProjection(
				'critical',
				__( 'Charter OAuth lockdown is active', 'charter' ),
				__( 'Credential issuance and every Charter Bearer request are blocked. Inspect the incident and explicitly resume when it is safe.', 'charter' )
			),
			self::ISSUANCE_PAUSED => self::siteHealthProjection(
				'recommended',
				__( 'Charter OAuth issuance is paused', 'charter' ),
				__( 'New registrations, authorizations, authorization-code exchanges, and refreshes are blocked. Existing access tokens remain usable.', 'charter' )
			),
			default => self::siteHealthProjection(
				'good',
				__( 'Charter OAuth is operating normally', 'charter' ),
				__( 'Credential issuance and Charter Bearer authentication are available.', 'charter' )
			),
		};
	}

	/** Clears only the current-site containment option during tests or uninstall. */
	public function delete(): void {
		delete_option( self::OPTION );
	}

	/**
	 * Reports whether a value is one accepted target mode.
	 *
	 * @param mixed $mode Candidate mode.
	 */
	public static function isMode( mixed $mode ): bool {
		return is_string( $mode ) && in_array( $mode, array( self::RESUMED, self::ISSUANCE_PAUSED, self::LOCKDOWN ), true );
	}

	/**
	 * Returns one WordPress Site Health result.
	 *
	 * @param string $status Result severity.
	 * @param string $label Result label.
	 * @param string $description Safe operator description.
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
			'test'        => 'charter_oauth_containment',
		);
	}

	/**
	 * Reports whether a value is one stable operator channel.
	 *
	 * @param mixed $actor Candidate actor channel.
	 */
	private static function isActor( mixed $actor ): bool {
		return is_string( $actor ) && in_array( $actor, array( self::ACTOR_SITE_ADMIN, self::ACTOR_NETWORK_ADMIN, self::ACTOR_WP_CLI ), true );
	}

	/**
	 * Returns one accepted mode or the fail-safe default.
	 *
	 * @param mixed $mode Stored mode.
	 */
	private static function validatedMode( mixed $mode ): string {
		return self::isMode( $mode ) && is_string( $mode ) ? $mode : self::RESUMED;
	}

	/**
	 * Returns one accepted actor channel or an empty default.
	 *
	 * @param mixed $actor Stored actor channel.
	 */
	private static function validatedActor( mixed $actor ): string {
		return self::isActor( $actor ) && is_string( $actor ) ? $actor : '';
	}

	/**
	 * Returns a stored positive integer or null.
	 *
	 * @param mixed $value Stored value.
	 */
	private static function nullablePositiveInteger( mixed $value ): ?int {
		if ( is_int( $value ) && 0 < $value ) {
			return $value;
		}
		if ( is_string( $value ) && ctype_digit( $value ) && 0 < (int) $value ) {
			return (int) $value;
		}

		return null;
	}

	/**
	 * Persists one exact non-secret operational record.
	 *
	 * @param array<string, mixed> $record Applied transition record.
	 * @phpstan-param ContainmentSnapshot $record
	 */
	private static function persist( array $record ): bool {
		return update_option( self::OPTION, $record, false ) || get_option( self::OPTION ) === $record;
	}
}
