<?php
/**
 * Disposable Slice 0 effective-root source seam.
 *
 * @package GalatanOvidiu\Charter
 */

declare(strict_types=1);

namespace GalatanOvidiu\Charter\Tests\Prototype\Multisite;

use RuntimeException;

/**
 * Captures root material in memory for credential behavior evidence only.
 *
 * The framing, fingerprint, derivation, and digest algorithms in this class are
 * disposable proof mechanics. They are not production algorithm selections.
 *
 * @since 0.1.0
 */
final class EffectiveRootKeySource {

	/**
	 * WordPress-derived root mode.
	 *
	 * @since 0.1.0
	 *
	 * @var string
	 */
	public const MODE_WORDPRESS = 'wordpress';

	/**
	 * Explicit root mode.
	 *
	 * @since 0.1.0
	 *
	 * @var string
	 */
	public const MODE_EXPLICIT = 'explicit';

	/**
	 * The fixed D27 effective WordPress salt order.
	 *
	 * @since 0.1.0
	 *
	 * @var list<string>
	 */
	public const WORDPRESS_SCHEMES = array(
		'auth',
		'secure_auth',
		'logged_in',
		'nonce',
	);

	/**
	 * Selected proof mode.
	 *
	 * @since 0.1.0
	 *
	 * @var string
	 */
	private string $mode;

	/**
	 * In-memory root snapshot.
	 *
	 * @since 0.1.0
	 *
	 * @var string
	 */
	private string $rootSnapshot;

	/**
	 * Names of the effective WordPress values captured by this source.
	 *
	 * @since 0.1.0
	 *
	 * @var list<string>
	 */
	private array $observedWordPressSchemes;

	/**
	 * Creates one in-memory root snapshot.
	 *
	 * @since 0.1.0
	 *
	 * @param string $mode Selected proof mode.
	 * @param string $rootSnapshot Root material retained in memory only.
	 * @param array  $observedWordPressSchemes Captured scheme names only.
	 * @phpstan-param list<string> $observedWordPressSchemes
	 */
	private function __construct( string $mode, string $rootSnapshot, array $observedWordPressSchemes ) {
		$this->mode                     = $mode;
		$this->rootSnapshot             = $rootSnapshot;
		$this->observedWordPressSchemes = $observedWordPressSchemes;
	}

	/**
	 * Captures all four current effective wp_salt() values in the D27 order.
	 *
	 * @since 0.1.0
	 *
	 * @return self The WordPress-derived in-memory snapshot.
	 */
	public static function fromWordPress(): self {
		$effectiveValues = array();

		foreach ( self::WORDPRESS_SCHEMES as $scheme ) {
			$effectiveValues[] = wp_salt( $scheme );
		}

		return new self(
			self::MODE_WORDPRESS,
			self::frame( $effectiveValues ),
			self::WORDPRESS_SCHEMES
		);
	}

	/**
	 * Captures the effective configured source with explicit-key precedence.
	 *
	 * @since 0.1.0
	 *
	 * @return self The selected in-memory snapshot.
	 * @throws RuntimeException When the explicit proof constant is not a non-empty string.
	 */
	public static function fromConfiguration(): self {
		if ( ! defined( 'CHARTER_SECRET_KEY' ) ) {
			return self::fromWordPress();
		}

		$explicitSnapshot = constant( 'CHARTER_SECRET_KEY' );

		if ( ! is_string( $explicitSnapshot ) || '' === $explicitSnapshot ) {
			throw new RuntimeException( 'The explicit Charter proof key must be a non-empty string.' );
		}

		return self::fromExplicitSnapshot( $explicitSnapshot );
	}

	/**
	 * Captures one explicit configuration snapshot for state-transition tests.
	 *
	 * @since 0.1.0
	 *
	 * @param string $snapshot Explicit root material retained in memory only.
	 * @return self The explicit in-memory snapshot.
	 * @throws RuntimeException When the snapshot is empty.
	 */
	public static function fromExplicitSnapshot( string $snapshot ): self {
		if ( '' === $snapshot ) {
			throw new RuntimeException( 'The explicit Charter proof key must be a non-empty string.' );
		}

		return new self( self::MODE_EXPLICIT, $snapshot, array() );
	}

	/**
	 * Returns the selected proof mode.
	 *
	 * @since 0.1.0
	 *
	 * @return string The selected mode.
	 */
	public function mode(): string {
		return $this->mode;
	}

	/**
	 * Reports whether the source uses an explicit configuration snapshot.
	 *
	 * @since 0.1.0
	 *
	 * @return bool Whether explicit mode is selected.
	 */
	public function usesExplicitSnapshot(): bool {
		return self::MODE_EXPLICIT === $this->mode;
	}

	/**
	 * Returns captured scheme names without returning any effective value.
	 *
	 * @since 0.1.0
	 *
	 * @return list<string> The captured schemes in call order.
	 */
	public function observedWordPressSchemes(): array {
		return $this->observedWordPressSchemes;
	}

	/**
	 * Compares two in-memory root snapshots without exposing either value.
	 *
	 * @since 0.1.0
	 *
	 * @param self $other Another root snapshot.
	 * @return bool Whether both source mode and material match.
	 */
	public function sameRootAs( self $other ): bool {
		return $this->mode === $other->mode
			&& hash_equals( $this->rootSnapshot, $other->rootSnapshot );
	}

	/**
	 * Returns a disposable non-secret fingerprint for explicit-key guarding.
	 *
	 * The fingerprint is proof state only. Its encoding is not a production
	 * storage-format selection and callers must not log its literal value.
	 *
	 * @since 0.1.0
	 *
	 * @return string The non-secret proof fingerprint.
	 */
	public function nonSecretFingerprint(): string {
		return hash( 'sha256', self::frame( array( $this->mode, $this->rootSnapshot ) ) );
	}

	/**
	 * Produces a disposable issuer/type-separated one-way credential digest.
	 *
	 * This method is an internal seam for DigestedProofCredentialStore. Tests
	 * should use the store's sanitized evidence API rather than expose or log
	 * the returned proof digest.
	 *
	 * @since 0.1.0
	 *
	 * @param string $issuer Exact opaque issuer identifier.
	 * @param string $credentialType Named proof credential type.
	 * @param string $credential Presented opaque proof credential.
	 * @return string The disposable one-way proof digest.
	 */
	public function credentialProofDigest( string $issuer, string $credentialType, string $credential ): string {
		$domainKey = hash_hmac(
			'sha256',
			self::frame( array( 'charter-slice0-disposable', $issuer, $credentialType ) ),
			$this->rootSnapshot,
			true
		);

		return hash_hmac( 'sha256', $credential, $domainKey );
	}

	/**
	 * Frames proof values without selecting a durable representation.
	 *
	 * @since 0.1.0
	 *
	 * @param array $values Values to frame in their supplied order.
	 * @phpstan-param list<string> $values
	 * @return string The disposable binary framing.
	 */
	private static function frame( array $values ): string {
		$framed = '';

		foreach ( $values as $value ) {
			$framed .= pack( 'N', strlen( $value ) ) . $value;
		}

		return $framed;
	}
}
