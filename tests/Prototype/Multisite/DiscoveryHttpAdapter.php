<?php
/**
 * Disposable Slice 0 discovery HTTP adapter.
 *
 * @package GalatanOvidiu\Charter
 */

declare(strict_types=1);

namespace GalatanOvidiu\Charter\Tests\Prototype\Multisite;

use WP;

/**
 * Publishes the minimum identity metadata at the real WordPress HTTP seam.
 *
 * @since 0.1.0
 */
final class DiscoveryHttpAdapter {

	/**
	 * The RFC 8414 root discovery path.
	 *
	 * @since 0.1.0
	 *
	 * @var string
	 */
	private const AUTHORIZATION_SERVER_PATH = '/.well-known/oauth-authorization-server';

	/**
	 * The RFC 9728 root discovery path.
	 *
	 * @since 0.1.0
	 *
	 * @var string
	 */
	private const PROTECTED_RESOURCE_PATH = '/.well-known/oauth-protected-resource';

	/**
	 * Registers the HTTP dispatcher.
	 *
	 * @since 0.1.0
	 */
	public static function register(): void {
		add_action( 'parse_request', array( self::class, 'dispatch' ), 0 );
	}

	/**
	 * Serves discovery only when the exact current issuer is Prepared or Enabled.
	 *
	 * @since 0.1.0
	 *
	 * @param WP $wordpress The parsed WordPress request.
	 */
	public static function dispatch( WP $wordpress ): void {
		unset( $wordpress );

		$path = wp_parse_url( $_SERVER['REQUEST_URI'] ?? '', PHP_URL_PATH );

		if ( self::AUTHORIZATION_SERVER_PATH !== $path && self::PROTECTED_RESOURCE_PATH !== $path ) {
			return;
		}

		$identity = SiteIssuerLifecycle::identityForCurrentSite();

		if ( ! $identity instanceof IssuerIdentity || ! $identity->isBareOriginForV1() ) {
			return;
		}

		$issuer = $identity->issuer();

		if ( SiteIssuerLifecycle::AVAILABLE === SiteIssuerLifecycle::stateFor( $issuer ) ) {
			return;
		}

		$metadata = self::AUTHORIZATION_SERVER_PATH === $path
			? array( 'issuer' => $issuer )
			: array( 'resource' => $issuer );

		status_header( 200 );
		header( 'Content-Type: application/json; charset=UTF-8' );
		header( 'Content-Location: ' . $issuer . $path );
		echo wp_json_encode( $metadata, JSON_UNESCAPED_SLASHES );
		exit;
	}
}
