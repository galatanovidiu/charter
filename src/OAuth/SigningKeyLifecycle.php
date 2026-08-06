<?php
/**
 * OAuth credential signing-key lifecycle.
 *
 * @package GalatanOvidiu\Charter
 */

declare(strict_types=1);

namespace GalatanOvidiu\Charter\OAuth;

use Closure;
use GalatanOvidiu\Charter\Cli\SigningKeyCommand;
use GalatanOvidiu\Charter\Security\AuditWriter;
use GalatanOvidiu\Charter\Site\SiteState;
use RuntimeException;

/**
 * Owns effective root-key selection and explicit replacement adoption.
 *
 * Root material and derived subkeys exist only in request memory. Persisted
 * state contains only an issuer-bound fingerprint and non-secret transition
 * metadata for the explicit deployment override.
 *
 * @since 0.1.0
 *
 * @phpstan-type SourceSnapshot array{source:string,root:?string,database_fallback:bool}
 * @phpstan-type GuardRecord array{issuer:string,accepted_fingerprint:string,generation:int,adoption_count:int,changed_at:int,actor:string,actor_user_id:?int,audit_pending:bool,transition_id:string}
 * @phpstan-type KeySnapshot array{source:string,status:string,database_fallback:bool,generation:int,adoption_count:int,changed_at:?int,actor:string,actor_user_id:?int,audit_pending:bool,mismatch_id:?string,transition_id:?string}
 */
final class SigningKeyLifecycle {

	public const SOURCE_WORDPRESS = 'wordpress';
	public const SOURCE_EXPLICIT  = 'explicit';

	public const STATUS_AUTOMATIC     = 'automatic';
	public const STATUS_MATCHING      = 'matching';
	public const STATUS_MISMATCH      = 'mismatch';
	public const STATUS_INVALID       = 'invalid';
	public const STATUS_UNESTABLISHED = 'unestablished';
	public const STATUS_UNAVAILABLE   = 'unavailable';

	public const ACTOR_INITIAL       = 'initial_configuration';
	public const ACTOR_SITE_ADMIN    = 'site_administrator';
	public const ACTOR_NETWORK_ADMIN = 'network_administrator';
	public const ACTOR_WP_CLI        = 'wp_cli';

	private const OPTION = 'charter_oauth_signing_key_guard';

	private const WORDPRESS_SALT_SCHEMES = array(
		'auth',
		'secure_auth',
		'logged_in',
		'nonce',
	);

	/**
	 * Resolves the request-local root source.
	 *
	 * @var Closure():mixed
	 */
	private readonly Closure $sourceResolver;

	/**
	 * Creates the issuer-local key lifecycle.
	 *
	 * The optional resolver is an internal test seam. Production always reads
	 * the deployment constant or the four effective WordPress salt APIs.
	 *
	 * @param SiteState    $siteState Current switched-site lifecycle.
	 * @param AuditWriter  $audit Secret-free current-site audit ledger.
	 * @param Closure|null $sourceResolver Optional request-local source resolver.
	 */
	public function __construct(
		private readonly SiteState $siteState,
		private readonly AuditWriter $audit,
		?Closure $sourceResolver = null
	) {
		$this->sourceResolver = $sourceResolver ?? self::defaultSourceResolver( ... );
	}

	/** Registers local operational diagnostics and WP-CLI. */
	public function registerHooks(): void {
		add_filter( 'site_status_tests', array( $this, 'registerSiteHealthTest' ) );
		add_action( 'admin_notices', array( $this, 'renderAdministratorNotice' ) );

		if ( defined( 'WP_CLI' ) && WP_CLI && class_exists( '\\WP_CLI' ) ) {
			\WP_CLI::add_command( 'charter oauth signing-key', new SigningKeyCommand( $this, $this->siteState ) );
		}
	}

	/**
	 * Produces one issuer- and type-separated credential digest.
	 *
	 * Generation zero intentionally preserves the original production digest
	 * domain. Explicit adoptions add a generation binding so returning to an
	 * earlier configured value cannot resurrect credentials from that value.
	 *
	 * @param string $issuer Exact issuer.
	 * @param string $credentialType Credential domain.
	 * @param string $credential Presented opaque credential.
	 * @throws RuntimeException When configured root material is invalid.
	 */
	public function digest( string $issuer, string $credentialType, string $credential ): string {
		$source = $this->source();
		$root   = $source['root'];
		if ( ! is_string( $root ) || '' === $root ) {
			throw new RuntimeException( 'charter_secret_key_invalid' );
		}

		$domain = array( 'charter-oauth-v1', $issuer, $credentialType );
		if ( self::SOURCE_EXPLICIT === $source['source'] ) {
			$record = $this->guardRecord();
			if ( null !== $record && $record['issuer'] === $issuer && 0 < $record['generation'] ) {
				$domain[] = 'explicit-generation';
				$domain[] = (string) $record['generation'];
			}
		}

		$domainKey = hash_hmac( 'sha256', self::frame( $domain ), $root, true );

		return hash_hmac( 'sha256', $credential, $domainKey );
	}

	/** Reports whether new credentials and Charter validation may proceed. */
	public function credentialOperationsAllowed(): bool {
		$snapshot = $this->snapshot();

		return self::STATUS_AUTOMATIC === $snapshot['status'] || self::STATUS_MATCHING === $snapshot['status'];
	}

	/**
	 * Returns truthful, secret-free current-site status.
	 *
	 * The first valid explicit value is established automatically. This keeps
	 * existing explicit deployments compatible when the guard is introduced;
	 * only later unexpected changes require explicit adoption.
	 *
	 * @phpstan-return KeySnapshot
	 */
	public function snapshot(): array {
		$source = $this->source();
		if ( self::SOURCE_WORDPRESS === $source['source'] ) {
			return array(
				'source'            => self::SOURCE_WORDPRESS,
				'status'            => self::STATUS_AUTOMATIC,
				'database_fallback' => $source['database_fallback'],
				'generation'        => 0,
				'adoption_count'    => 0,
				'changed_at'        => null,
				'actor'             => '',
				'actor_user_id'     => null,
				'audit_pending'     => false,
				'mismatch_id'       => null,
				'transition_id'     => null,
			);
		}

		$identity = $this->siteState->identity();
		if ( null === $identity ) {
			return self::unavailableSnapshot( self::STATUS_UNAVAILABLE );
		}
		$root = $source['root'];
		if ( ! is_string( $root ) || '' === $root ) {
			return self::unavailableSnapshot( self::STATUS_INVALID );
		}

		$issuer      = $identity->issuer();
		$fingerprint = self::fingerprint( $issuer, $root );
		$record      = $this->guardRecord();
		if ( null === $record ) {
			if ( $this->guardOptionExists() ) {
				return self::unavailableSnapshot( self::STATUS_UNESTABLISHED );
			}
			$record = $this->establish( $issuer, $fingerprint );
			if ( null === $record ) {
				return self::unavailableSnapshot( self::STATUS_UNESTABLISHED );
			}
		}

		$matching = $record['issuer'] === $issuer && hash_equals( $record['accepted_fingerprint'], $fingerprint );

		return array(
			'source'            => self::SOURCE_EXPLICIT,
			'status'            => $matching ? self::STATUS_MATCHING : self::STATUS_MISMATCH,
			'database_fallback' => false,
			'generation'        => $record['generation'],
			'adoption_count'    => $record['adoption_count'],
			'changed_at'        => $record['changed_at'],
			'actor'             => $record['actor'],
			'actor_user_id'     => $record['actor_user_id'],
			'audit_pending'     => $record['audit_pending'],
			'mismatch_id'       => $matching ? null : self::mismatchId( $issuer, $record, $fingerprint ),
			'transition_id'     => '' === $record['transition_id'] ? null : $record['transition_id'],
		);
	}

	/**
	 * Adopts the exact current explicit replacement for this enabled issuer.
	 *
	 * @param string   $actor Stable operator channel.
	 * @param int|null $actorUserId WordPress operator identity, when applicable.
	 * @param int      $timestamp Current Unix timestamp.
	 * @param string   $expectedIssuer Exact issuer bound by the operator action.
	 * @param string   $expectedMismatchId Exact non-secret mismatch binding.
	 */
	public function adoptReplacement( string $actor, ?int $actorUserId, int $timestamp, string $expectedIssuer, string $expectedMismatchId ): bool {
		$identity = $this->siteState->identity();
		if (
			null === $identity
			|| ! $this->siteState->isEnabled()
			|| ! self::isActor( $actor )
			|| $timestamp <= 0
			|| '' === $expectedMismatchId
			|| ( self::ACTOR_WP_CLI !== $actor && ( null === $actorUserId || $actorUserId <= 0 ) )
			|| ! hash_equals( $identity->issuer(), $expectedIssuer )
		) {
			return false;
		}

		$source = $this->source();
		$root   = $source['root'];
		$record = $this->guardRecord();
		if ( self::SOURCE_EXPLICIT !== $source['source'] || ! is_string( $root ) || '' === $root || null === $record || $record['audit_pending'] || $record['issuer'] !== $expectedIssuer ) {
			return false;
		}

		$fingerprint = self::fingerprint( $expectedIssuer, $root );
		$mismatchId  = self::mismatchId( $expectedIssuer, $record, $fingerprint );
		if ( hash_equals( $record['accepted_fingerprint'], $fingerprint ) || ! hash_equals( $mismatchId, $expectedMismatchId ) ) {
			return false;
		}

		$changedAt   = max( $timestamp, $record['changed_at'] + 1 );
		$generation  = $record['generation'] + 1;
		$transition  = hash( 'sha256', self::frame( array( 'charter-oauth-v1-key-adoption', $expectedIssuer, (string) $generation, (string) $changedAt, $actor ) ) );
		$replacement = array(
			'issuer'               => $expectedIssuer,
			'accepted_fingerprint' => $fingerprint,
			'generation'           => $generation,
			'adoption_count'       => $record['adoption_count'] + 1,
			'changed_at'           => $changedAt,
			'actor'                => $actor,
			'actor_user_id'        => $actorUserId,
			'audit_pending'        => true,
			'transition_id'        => $transition,
		);
		if ( ! self::persist( $replacement ) ) {
			return false;
		}

		$this->reconcileAudit( $replacement );

		return true;
	}

	/**
	 * Retries one already-applied adoption's exact pending audit record.
	 *
	 * @param string $expectedIssuer Exact current issuer.
	 * @param string $expectedTransitionId Exact pending transition binding.
	 */
	public function reconcilePendingAudit( string $expectedIssuer, string $expectedTransitionId ): bool {
		$identity = $this->siteState->identity();
		$record   = $this->guardRecord();
		if (
			null === $identity
			|| null === $record
			|| ! $record['audit_pending']
			|| '' === $expectedTransitionId
			|| ! hash_equals( $identity->issuer(), $expectedIssuer )
			|| ! hash_equals( $record['issuer'], $expectedIssuer )
			|| ! hash_equals( $record['transition_id'], $expectedTransitionId )
		) {
			return false;
		}

		return $this->reconcileAudit( $record );
	}

	/**
	 * Adds the signing-key diagnostic to Site Health.
	 *
	 * @param array<string, mixed> $tests Registered Site Health tests.
	 * @return array<string, mixed>
	 */
	public function registerSiteHealthTest( array $tests ): array {
		$direct                              = $tests['direct'] ?? array();
		$direct                              = is_array( $direct ) ? $direct : array();
		$direct['charter_oauth_signing_key'] = array(
			'label' => __( 'Charter OAuth credential signing key', 'charter' ),
			'test'  => array( $this, 'siteHealthResult' ),
		);
		$tests['direct']                     = $direct;

		return $tests;
	}

	/**
	 * Projects one truthful, secret-free Site Health result.
	 *
	 * @return array{status:string,label:string,badge:array{label:string,color:string},description:string,test:string}
	 */
	public function siteHealthResult(): array {
		if ( null === $this->siteState->identity() || ! $this->siteState->isEnabled() ) {
			return self::siteHealthProjection( 'good', __( 'Charter OAuth signing-key enforcement is inactive', 'charter' ), __( 'This site has no enabled Charter OAuth issuer requiring credential-key enforcement.', 'charter' ) );
		}

		$snapshot = $this->snapshot();
		if ( self::STATUS_MISMATCH === $snapshot['status'] ) {
			return self::siteHealthProjection( 'critical', __( 'The explicit Charter OAuth key does not match', 'charter' ), __( 'OAuth credential issuance and Charter credential validation are blocked. Restore the prior CHARTER_SECRET_KEY value or explicitly adopt the current replacement.', 'charter' ) );
		}
		if ( in_array( $snapshot['status'], array( self::STATUS_INVALID, self::STATUS_UNESTABLISHED, self::STATUS_UNAVAILABLE ), true ) ) {
			return self::siteHealthProjection( 'critical', __( 'The Charter OAuth signing key is unavailable', 'charter' ), __( 'OAuth credential issuance and Charter credential validation are blocked until valid issuer-local key state is available.', 'charter' ) );
		}
		if ( $snapshot['audit_pending'] ) {
			return self::siteHealthProjection( 'critical', __( 'The Charter OAuth key-adoption audit is incomplete', 'charter' ), __( 'The explicit replacement is active, but its secret-free audit event is pending reconciliation.', 'charter' ) );
		}
		if ( self::SOURCE_WORDPRESS === $snapshot['source'] && $snapshot['database_fallback'] ) {
			return self::siteHealthProjection( 'recommended', __( 'Charter OAuth uses database-backed WordPress secret material', 'charter' ), __( 'OAuth remains operational and follows current effective WordPress salts. Deployment configuration can provide stronger separation from a database compromise.', 'charter' ) );
		}

		$description = self::SOURCE_EXPLICIT === $snapshot['source']
			? __( 'The current explicit CHARTER_SECRET_KEY matches this issuer’s accepted non-secret fingerprint.', 'charter' )
			: __( 'Charter OAuth automatically follows the four current effective WordPress salt values.', 'charter' );

		return self::siteHealthProjection( 'good', __( 'The Charter OAuth signing key is available', 'charter' ), $description );
	}

	/** Shows a persistent Site Admin warning while operator action is required. */
	public function renderAdministratorNotice(): void {
		if ( ! current_user_can( 'manage_options' ) || ! $this->siteState->isEnabled() ) {
			return;
		}
		$snapshot = $this->snapshot();
		if ( self::STATUS_MISMATCH === $snapshot['status'] ) {
			$message = __( 'Charter OAuth is blocking credential issuance and Charter credential validation because CHARTER_SECRET_KEY does not match this site issuer. Restore the prior value or explicitly adopt the replacement in Charter OAuth settings.', 'charter' );
		} elseif ( in_array( $snapshot['status'], array( self::STATUS_INVALID, self::STATUS_UNESTABLISHED, self::STATUS_UNAVAILABLE ), true ) ) {
			$message = __( 'Charter OAuth is blocking credential issuance and Charter credential validation because its explicit signing-key state is unavailable.', 'charter' );
		} elseif ( $snapshot['audit_pending'] ) {
			$message = __( 'The current Charter OAuth explicit-key replacement is active, but its secret-free audit event still requires reconciliation in Charter OAuth settings.', 'charter' );
		} else {
			return;
		}
		?>
		<div class="notice notice-error"><p><?php echo esc_html( $message ); ?></p></div>
		<?php
	}

	/** Clears only the current-site guard option during tests or uninstall. */
	public function delete(): void {
		delete_option( self::OPTION );
	}

	/**
	 * Reports whether a value is one stable operator channel.
	 *
	 * @param mixed $actor Candidate actor.
	 */
	private static function isActor( mixed $actor ): bool {
		return is_string( $actor ) && in_array( $actor, array( self::ACTOR_SITE_ADMIN, self::ACTOR_NETWORK_ADMIN, self::ACTOR_WP_CLI ), true );
	}

	/**
	 * Establishes generation zero for the first valid explicit deployment key.
	 *
	 * @param string $issuer Exact current issuer.
	 * @param string $fingerprint Non-secret issuer-bound fingerprint.
	 * @phpstan-return GuardRecord|null
	 */
	private function establish( string $issuer, string $fingerprint ): ?array {
		$record = array(
			'issuer'               => $issuer,
			'accepted_fingerprint' => $fingerprint,
			'generation'           => 0,
			'adoption_count'       => 0,
			'changed_at'           => time(),
			'actor'                => self::ACTOR_INITIAL,
			'actor_user_id'        => null,
			'audit_pending'        => false,
			'transition_id'        => '',
		);

		return self::persist( $record ) ? $record : null;
	}

	/**
	 * Records and reconciles one already-applied explicit replacement.
	 *
	 * @param array<string, mixed> $record Applied guard transition.
	 * @phpstan-param GuardRecord $record
	 */
	private function reconcileAudit( array $record ): bool {
		$reason = $record['actor'] . '_explicit_key_replacement';
		try {
			if ( ! $this->audit->hasEvent( $record['issuer'], $record['changed_at'], 'root_key_replacement_adopted', 'success', $reason, $record['actor_user_id'] ) ) {
				$this->audit->record(
					$record['issuer'],
					'root_key_replacement_adopted',
					'success',
					$reason,
					$record['actor_user_id'],
					null,
					null,
					null,
					$record['changed_at']
				);
			}
		} catch ( RuntimeException ) {
			return false;
		}
		$record['audit_pending'] = false;

		return self::persist( $record );
	}

	/**
	 * Returns one validated persisted guard record.
	 *
	 * @phpstan-return GuardRecord|null
	 */
	private function guardRecord(): ?array {
		$record = get_option( self::OPTION, null );
		if ( ! is_array( $record ) ) {
			return null;
		}

		$issuer          = $record['issuer'] ?? null;
		$fingerprint     = $record['accepted_fingerprint'] ?? null;
		$generation      = self::nonNegativeInteger( $record['generation'] ?? null );
		$adoptionCount   = self::nonNegativeInteger( $record['adoption_count'] ?? null );
		$changedAt       = self::positiveInteger( $record['changed_at'] ?? null );
		$actor           = $record['actor'] ?? null;
		$actorUserId     = self::nullablePositiveInteger( $record['actor_user_id'] ?? null );
		$auditPending    = true === ( $record['audit_pending'] ?? false );
		$transitionId    = $record['transition_id'] ?? null;
		$actorStateValid = match ( $actor ) {
			self::ACTOR_INITIAL => 0 === $generation && 0 === $adoptionCount && null === $actorUserId && ! $auditPending && '' === $transitionId,
			self::ACTOR_SITE_ADMIN, self::ACTOR_NETWORK_ADMIN => 0 < $generation && $generation === $adoptionCount && null !== $actorUserId && '' !== $transitionId,
			self::ACTOR_WP_CLI => 0 < $generation && $generation === $adoptionCount && null === $actorUserId && '' !== $transitionId,
			default => false,
		};
		if (
			! is_string( $issuer ) || '' === $issuer
			|| ! is_string( $fingerprint ) || 1 !== preg_match( '/^[a-f0-9]{64}$/D', $fingerprint )
			|| null === $generation || null === $adoptionCount || null === $changedAt
			|| ! is_string( $actor )
			|| ! $actorStateValid
			|| ! is_string( $transitionId ) || ( '' !== $transitionId && 1 !== preg_match( '/^[a-f0-9]{64}$/D', $transitionId ) )
			|| ( $auditPending && '' === $transitionId )
		) {
			return null;
		}

		return array(
			'issuer'               => $issuer,
			'accepted_fingerprint' => $fingerprint,
			'generation'           => $generation,
			'adoption_count'       => $adoptionCount,
			'changed_at'           => $changedAt,
			'actor'                => $actor,
			'actor_user_id'        => $actorUserId,
			'audit_pending'        => $auditPending,
			'transition_id'        => $transitionId,
		);
	}

	/** Reports whether any persisted guard value exists, including malformed state. */
	private function guardOptionExists(): bool {
		$missing = new \stdClass();

		return get_option( self::OPTION, $missing ) !== $missing;
	}

	/**
	 * Resolves and validates the configured request-local root source.
	 *
	 * @phpstan-return SourceSnapshot
	 * @throws RuntimeException When the source resolver returns invalid state.
	 */
	private function source(): array {
		$source = ( $this->sourceResolver )();
		if (
			! is_array( $source )
			|| ! is_string( $source['source'] ?? null )
			|| ! in_array( $source['source'], array( self::SOURCE_WORDPRESS, self::SOURCE_EXPLICIT ), true )
			|| ! array_key_exists( 'root', $source )
			|| ( null !== $source['root'] && ! is_string( $source['root'] ) )
			|| ! is_bool( $source['database_fallback'] ?? null )
		) {
			throw new RuntimeException( 'charter_signing_key_source_invalid' );
		}

		return $source;
	}

	/**
	 * Selects explicit configuration or the four effective WordPress salts.
	 *
	 * @phpstan-return SourceSnapshot
	 */
	private static function defaultSourceResolver(): array {
		if ( defined( 'CHARTER_SECRET_KEY' ) ) {
			$explicit = constant( 'CHARTER_SECRET_KEY' );

			return array(
				'source'            => self::SOURCE_EXPLICIT,
				'root'              => is_string( $explicit ) && '' !== $explicit ? $explicit : null,
				'database_fallback' => false,
			);
		}

		$values = array();
		foreach ( self::WORDPRESS_SALT_SCHEMES as $scheme ) {
			$values[] = wp_salt( $scheme );
		}

		return array(
			'source'            => self::SOURCE_WORDPRESS,
			'root'              => self::frame( $values ),
			'database_fallback' => self::usesDatabaseFallback(),
		);
	}

	/** Conservatively detects when WordPress must supply fallback secret state. */
	private static function usesDatabaseFallback(): bool {
		$constants = array( 'AUTH_KEY', 'AUTH_SALT', 'SECURE_AUTH_KEY', 'SECURE_AUTH_SALT', 'LOGGED_IN_KEY', 'LOGGED_IN_SALT', 'NONCE_KEY', 'NONCE_SALT' );
		$seen      = array();
		foreach ( $constants as $name ) {
			if ( ! defined( $name ) ) {
				return true;
			}
			$value = constant( $name );
			if ( ! is_string( $value ) || '' === $value || 'put your unique phrase here' === $value || in_array( $value, $seen, true ) ) {
				return true;
			}
			$seen[] = $value;
		}

		return false;
	}

	/**
	 * Returns an issuer-bound non-secret explicit-key fingerprint.
	 *
	 * @param string $issuer Exact issuer.
	 * @param string $root Request-local explicit root material.
	 */
	private static function fingerprint( string $issuer, string $root ): string {
		return hash( 'sha256', self::frame( array( 'charter-oauth-v1-explicit-key-fingerprint', $issuer, $root ) ) );
	}

	/**
	 * Returns one exact current mismatch binding without exposing key material.
	 *
	 * @param string               $issuer Exact issuer.
	 * @param array<string, mixed> $record Accepted guard record.
	 * @param string               $currentFingerprint Current non-secret fingerprint.
	 * @phpstan-param GuardRecord $record
	 */
	private static function mismatchId( string $issuer, array $record, string $currentFingerprint ): string {
		return hash( 'sha256', self::frame( array( 'charter-oauth-v1-explicit-key-mismatch', $issuer, (string) $record['generation'], $record['accepted_fingerprint'], $currentFingerprint ) ) );
	}

	/**
	 * Returns a fail-closed explicit-source projection.
	 *
	 * @param string $status Stable failure status.
	 * @phpstan-return KeySnapshot
	 */
	private static function unavailableSnapshot( string $status ): array {
		return array(
			'source'            => self::SOURCE_EXPLICIT,
			'status'            => $status,
			'database_fallback' => false,
			'generation'        => 0,
			'adoption_count'    => 0,
			'changed_at'        => null,
			'actor'             => '',
			'actor_user_id'     => null,
			'audit_pending'     => false,
			'mismatch_id'       => null,
			'transition_id'     => null,
		);
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
			'test'        => 'charter_oauth_signing_key',
		);
	}

	/**
	 * Persists one exact non-secret guard record.
	 *
	 * @param array<string, mixed> $record Validated guard record.
	 * @phpstan-param GuardRecord $record
	 */
	private static function persist( array $record ): bool {
		return update_option( self::OPTION, $record, false ) || get_option( self::OPTION ) === $record;
	}

	/**
	 * Frames variable-length values without delimiter ambiguity.
	 *
	 * @param array<string> $values Values to frame.
	 */
	private static function frame( array $values ): string {
		$framed = '';
		foreach ( $values as $value ) {
			$framed .= strlen( $value ) . ':' . $value;
		}

		return $framed;
	}

	/**
	 * Returns a stored positive integer or null.
	 *
	 * @param mixed $value Stored value.
	 */
	private static function positiveInteger( mixed $value ): ?int {
		if ( is_int( $value ) && 0 < $value ) {
			return $value;
		}
		if ( is_string( $value ) && ctype_digit( $value ) && 0 < (int) $value ) {
			return (int) $value;
		}

		return null;
	}

	/**
	 * Returns a stored non-negative integer or null.
	 *
	 * @param mixed $value Stored value.
	 */
	private static function nonNegativeInteger( mixed $value ): ?int {
		if ( is_int( $value ) && 0 <= $value ) {
			return $value;
		}
		if ( is_string( $value ) && ctype_digit( $value ) ) {
			return (int) $value;
		}

		return null;
	}

	/**
	 * Returns a stored positive integer or null.
	 *
	 * @param mixed $value Stored nullable value.
	 */
	private static function nullablePositiveInteger( mixed $value ): ?int {
		return null === $value ? null : self::positiveInteger( $value );
	}
}
