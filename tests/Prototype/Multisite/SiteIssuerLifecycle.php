<?php
/**
 * Disposable Slice 0 site issuer lifecycle seam.
 *
 * @package GalatanOvidiu\Charter
 */

declare(strict_types=1);

namespace GalatanOvidiu\Charter\Tests\Prototype\Multisite;

/**
 * Exposes issuer-addressed lifecycle state without exposing persistence details.
 *
 * @since 0.1.0
 */
final class SiteIssuerLifecycle {

	/**
	 * The lifecycle state for a site with no prepared issuer.
	 *
	 * @since 0.1.0
	 *
	 * @var string
	 */
	public const AVAILABLE = 'available';

	/**
	 * The lifecycle state for a prepared site issuer.
	 *
	 * @since 0.1.0
	 *
	 * @var string
	 */
	public const PREPARED = 'prepared';

	/**
	 * The lifecycle state for a verified and enabled site issuer.
	 *
	 * @since 0.1.0
	 *
	 * @var string
	 */
	public const ENABLED = 'enabled';

	/**
	 * Disposable network option used by the proof store.
	 *
	 * @since 0.1.0
	 *
	 * @var string
	 */
	private const STORE_OPTION = 'charter_slice0_site_issuer_records';

	/**
	 * Prepares one exact site issuer.
	 *
	 * @since 0.1.0
	 *
	 * @param IssuerIdentity $identity The explicit site issuer identity.
	 */
	public static function prepare( IssuerIdentity $identity ): void {
		$records                        = self::records();
		$records[ $identity->issuer() ] = array(
			'site_id' => $identity->siteId(),
			'state'   => self::PREPARED,
		);

		update_network_option( null, self::STORE_OPTION, $records );
	}

	/**
	 * Returns the lifecycle state for one exact issuer.
	 *
	 * @since 0.1.0
	 *
	 * @param string $issuer The exact issuer identifier.
	 * @return string The lifecycle state.
	 */
	public static function stateFor( string $issuer ): string {
		$records = self::records();

		return $records[ $issuer ]['state'] ?? self::AVAILABLE;
	}

	/**
	 * Reports whether the proof store contains an exact issuer.
	 *
	 * @since 0.1.0
	 *
	 * @param string $issuer The exact issuer identifier.
	 * @return bool Whether the issuer exists.
	 */
	public static function hasIssuer( string $issuer ): bool {
		return array_key_exists( $issuer, self::records() );
	}

	/**
	 * Records manual verification for one exact prepared issuer.
	 *
	 * @since 0.1.0
	 *
	 * @param string $issuer The exact verified issuer identifier.
	 * @return bool Whether verification was recorded.
	 */
	public static function recordVerification( string $issuer ): bool {
		$records = self::records();

		if ( ! isset( $records[ $issuer ] ) ) {
			return false;
		}

		$records[ $issuer ]['verified_issuer'] = $issuer;
		update_network_option( null, self::STORE_OPTION, $records );

		return true;
	}

	/**
	 * Enables only an issuer with verification recorded for that exact identity.
	 *
	 * @since 0.1.0
	 *
	 * @param string $issuer The exact issuer identifier to enable.
	 * @return bool Whether the issuer was enabled.
	 */
	public static function enable( string $issuer ): bool {
		$records = self::records();

		if ( ! isset( $records[ $issuer ] ) || ( $records[ $issuer ]['verified_issuer'] ?? null ) !== $issuer ) {
			return false;
		}

		$records[ $issuer ]['state'] = self::ENABLED;
		update_network_option( null, self::STORE_OPTION, $records );

		return true;
	}

	/**
	 * Reports whether one exact identity may execute a v1 operation.
	 *
	 * @since 0.1.0
	 *
	 * @param IssuerIdentity $identity The explicit site issuer identity.
	 * @return bool Whether the issuer is both supported and Enabled.
	 */
	public static function isEnabledForV1Operation( IssuerIdentity $identity ): bool {
		return $identity->isBareOriginForV1()
			&& self::ENABLED === self::stateFor( $identity->issuer() );
	}

	/**
	 * Clears all disposable proof records between integration tests.
	 *
	 * @since 0.1.0
	 */
	public static function resetProof(): void {
		delete_network_option( null, self::STORE_OPTION );
	}

	/**
	 * Reads all issuer-addressed proof records.
	 *
	 * @since 0.1.0
	 *
	 * @return array<string, array{site_id: int, state: string, verified_issuer?: string}> The proof records.
	 */
	private static function records(): array {
		$records = get_network_option( null, self::STORE_OPTION, array() );

		return is_array( $records ) ? $records : array();
	}
}
