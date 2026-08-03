<?php
/**
 * Disposable Slice 0 non-discovery operation HTTP adapter.
 *
 * @package GalatanOvidiu\Charter
 */

declare(strict_types=1);

namespace GalatanOvidiu\Charter\Tests\Prototype\Multisite;

use WP;

/**
 * Exposes one test-only operation behind the issuer lifecycle guard.
 *
 * @since 0.1.0
 */
final class OperationProbeHttpAdapter {

	/**
	 * The deliberately non-protocol proof path.
	 *
	 * @since 0.1.0
	 *
	 * @var string
	 */
	private const PATH = '/charter-slice0-operation-probe';

	/**
	 * Registers the HTTP dispatcher.
	 *
	 * @since 0.1.0
	 */
	public static function register(): void {
		add_action( 'parse_request', array( self::class, 'dispatch' ), 0 );
	}

	/**
	 * Rejects Prepared and succeeds only for the exact Enabled issuer.
	 *
	 * @since 0.1.0
	 *
	 * @param WP $wordpress The parsed WordPress request.
	 */
	public static function dispatch( WP $wordpress ): void {
		unset( $wordpress );

		if ( self::PATH !== wp_parse_url( $_SERVER['REQUEST_URI'] ?? '', PHP_URL_PATH ) ) {
			return;
		}

		$identity = IssuerIdentity::forCurrentSite();
		$issuer   = $identity->issuer();
		$state    = SiteIssuerLifecycle::stateFor( $issuer );

		if ( SiteIssuerLifecycle::AVAILABLE === $state ) {
			return;
		}

		header( 'Content-Type: application/json; charset=UTF-8' );

		if ( ! SiteIssuerLifecycle::isEnabledForV1Operation( $identity ) ) {
			status_header( 403 );
			echo wp_json_encode( array( 'error' => 'issuer_not_enabled' ) );
			exit;
		}

		status_header( 200 );
		echo wp_json_encode(
			array(
				'issuer' => $issuer,
				'state'  => SiteIssuerLifecycle::ENABLED,
			),
			JSON_UNESCAPED_SLASHES
		);
		exit;
	}
}
