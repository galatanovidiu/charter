<?php
/**
 * Site OAuth lifecycle state.
 *
 * @package GalatanOvidiu\Charter
 */

declare(strict_types=1);

namespace GalatanOvidiu\Charter\Site;

use GalatanOvidiu\Charter\Security\TrustedProxyPolicy;
use InvalidArgumentException;

/**
 * Owns the current site's canonical issuer and Available/Prepared/Enabled state.
 *
 * @since 0.1.0
 */
final class SiteState {

	public const AVAILABLE = 'available';
	public const PREPARED  = 'prepared';
	public const ENABLED   = 'enabled';

	private const OPTION = 'charter_oauth_site_state';

	/**
	 * Prepares the current site using its public WordPress home URL.
	 *
	 * @since 0.1.0
	 *
	 * @return bool Whether a supported identity was prepared.
	 */
	public function prepareCurrentSite(): bool {
		try {
			$developmentMode   = self::developmentMode();
			$developmentHosts  = self::developmentHosts();
			$identity          = SiteIdentity::fromUrl(
				home_url( '/' ),
				$developmentMode,
				$developmentHosts
			);
			$wordpressIdentity = SiteIdentity::fromUrl( site_url( '/' ), $developmentMode, $developmentHosts );
		} catch ( InvalidArgumentException $exception ) {
			$this->recordUnavailableError( $exception->getMessage() );

			return false;
		}
		if ( $wordpressIdentity->issuer() !== $identity->issuer() ) {
			$this->recordUnavailableError( 'charter_wordpress_must_be_installed_at_issuer_origin' );

			return false;
		}

		$current = $this->record();
		if (
			( $current['issuer'] ?? null ) === $identity->issuer()
			&& in_array( $current['state'] ?? null, array( self::PREPARED, self::ENABLED ), true )
		) {
			return true;
		}

		return $this->persist(
			array(
				'state'           => self::PREPARED,
				'issuer'          => $identity->issuer(),
				'verified_issuer' => null,
			)
		);
	}

	/**
	 * Records manual discovery verification for the exact current issuer.
	 *
	 * @since 0.1.0
	 *
	 * @param string $issuer Exact verified issuer.
	 * @return bool Whether verification was recorded.
	 */
	public function recordDiscoveryVerification( string $issuer ): bool {
		$record = $this->record();

		if ( self::PREPARED !== ( $record['state'] ?? null ) || ( $record['issuer'] ?? null ) !== $issuer ) {
			return false;
		}

		if ( ( $record['verified_issuer'] ?? null ) === $issuer ) {
			return true;
		}

		$record['verified_issuer'] = $issuer;

		return $this->persist( $record );
	}

	/**
	 * Enables an exactly verified prepared issuer.
	 *
	 * @since 0.1.0
	 *
	 * @param string $issuer Exact issuer to enable.
	 * @return bool Whether the transition completed.
	 */
	public function enable( string $issuer ): bool {
		$record = $this->record();

		if ( ( $record['issuer'] ?? null ) !== $issuer || ( $record['verified_issuer'] ?? null ) !== $issuer ) {
			return false;
		}
		if ( self::ENABLED === ( $record['state'] ?? null ) ) {
			return true;
		}
		if ( self::PREPARED !== ( $record['state'] ?? null ) ) {
			return false;
		}

		$record['state'] = self::ENABLED;

		return $this->persist( $record );
	}

	/**
	 * Returns the current lifecycle state.
	 *
	 * @since 0.1.0
	 */
	public function state(): string {
		$state = $this->record()['state'] ?? self::AVAILABLE;

		return in_array( $state, array( self::AVAILABLE, self::PREPARED, self::ENABLED ), true )
			? $state
			: self::AVAILABLE;
	}

	/**
	 * Returns the current exact identity when one is prepared.
	 *
	 * @since 0.1.0
	 */
	public function identity(): ?SiteIdentity {
		$issuer = $this->record()['issuer'] ?? null;

		if ( ! is_string( $issuer ) ) {
			return null;
		}

		try {
			return SiteIdentity::fromUrl( $issuer, self::developmentMode(), self::developmentHosts() );
		} catch ( InvalidArgumentException ) {
			return null;
		}
	}

	/**
	 * Reports whether discovery may be published.
	 *
	 * @since 0.1.0
	 */
	public function publishesMetadata(): bool {
		return null !== $this->identity() && in_array( $this->state(), array( self::PREPARED, self::ENABLED ), true );
	}

	/**
	 * Reports whether non-discovery OAuth behavior may execute.
	 *
	 * @since 0.1.0
	 */
	public function isEnabled(): bool {
		return null !== $this->identity() && self::ENABLED === $this->state();
	}

	/**
	 * Reports whether the direct request origin matches the stored identity.
	 *
	 * Forwarded headers are deliberately ignored until a trusted-proxy policy is
	 * configured. Non-HTTP CLI work has no request origin to compare.
	 *
	 * @since 0.1.0
	 */
	public function requestMatchesIdentity(): bool {
		$identity = $this->identity();
		if ( null === $identity ) {
			return false;
		}

		$requestHost = $_SERVER['HTTP_HOST'] ?? null; // phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotSanitized,WordPress.Security.ValidatedSanitizedInput.MissingUnslash -- Raw server transport metadata is parsed and compared, never used to construct the canonical identity.
		if ( ! is_string( $requestHost ) || '' === $requestHost ) {
			return 'cli' === PHP_SAPI;
		}
		$requestOrigin = ( new TrustedProxyPolicy() )->publicOrigin( $_SERVER, is_ssl() );
		if ( null === $requestOrigin ) {
			return false;
		}

		try {
			$requestIdentity = SiteIdentity::fromUrl(
				$requestOrigin,
				self::developmentMode(),
				self::developmentHosts()
			);
		} catch ( InvalidArgumentException ) {
			return false;
		}

		return hash_equals( $identity->issuer(), $requestIdentity->issuer() );
	}

	/** Registers deployment-boundary diagnostics with WordPress Site Health. */
	public function registerHooks(): void {
		add_filter( 'site_status_tests', array( $this, 'registerSiteHealthTest' ) );
	}

	/**
	 * Adds the current site's proxy and development-mode diagnostic.
	 *
	 * @param array<string, mixed> $tests Registered Site Health tests.
	 * @return array<string, mixed>
	 */
	public function registerSiteHealthTest( array $tests ): array {
		$direct                             = $tests['direct'] ?? array();
		$direct                             = is_array( $direct ) ? $direct : array();
		$direct['charter_oauth_public_url'] = array(
			'label' => __( 'Charter OAuth public URL and proxy trust', 'charter' ),
			'test'  => array( $this, 'siteHealthResult' ),
		);
		$tests['direct']                    = $direct;

		return $tests;
	}

	/**
	 * Projects the request-origin security boundary for Site Health.
	 *
	 * @return array{status:string,label:string,badge:array{label:string,color:string},description:string,test:string}
	 */
	public function siteHealthResult(): array {
		$policy = new TrustedProxyPolicy();
		if ( ! $policy->configurationValid() ) {
			return self::siteHealthProjection(
				'critical',
				__( 'Charter trusted-proxy configuration is invalid', 'charter' ),
				__( 'CHARTER_TRUSTED_PROXIES must be an array containing only exact IP addresses or CIDR networks. Forwarded origin data is disabled until this is corrected.', 'charter' )
			);
		}

		$forwardedPresent = isset( $_SERVER['HTTP_X_FORWARDED_FOR'] )
			|| isset( $_SERVER['HTTP_X_FORWARDED_HOST'] )
			|| isset( $_SERVER['HTTP_X_FORWARDED_PROTO'] )
			|| isset( $_SERVER['HTTP_X_FORWARDED_PORT'] );
		if ( $forwardedPresent && ! $policy->immediatePeerTrusted( $_SERVER ) ) {
			return self::siteHealthProjection(
				'recommended',
				__( 'Charter is ignoring untrusted proxy headers', 'charter' ),
				__( 'The immediate peer is not in CHARTER_TRUSTED_PROXIES. Charter safely uses the direct peer for abuse buckets, which may group many users behind one proxy, and ignores forwarded public-origin values.', 'charter' )
			);
		}
		if ( $forwardedPresent && null === $policy->publicOrigin( $_SERVER, is_ssl() ) ) {
			return self::siteHealthProjection(
				'critical',
				__( 'Charter cannot validate the forwarded public URL', 'charter' ),
				__( 'The trusted proxy supplied malformed or ambiguous forwarded host, protocol, or port values. OAuth endpoints fail closed until the proxy sends one canonical public origin.', 'charter' )
			);
		}

		$identity = $this->identity();
		if ( null !== $identity && str_starts_with( $identity->issuer(), 'http://' ) ) {
			return self::siteHealthProjection(
				'recommended',
				__( 'Charter OAuth is using insecure development mode', 'charter' ),
				__( 'This issuer uses HTTP under the explicit local-development exception. Do not use this configuration for production OAuth credentials.', 'charter' )
			);
		}

		return self::siteHealthProjection(
			'good',
			__( 'Charter OAuth public URL trust is configured', 'charter' ),
			$policy->configured()
				? __( 'Forwarded origin and client-address values are accepted only from the configured immediate proxy networks.', 'charter' )
				: __( 'Charter uses the direct request origin and peer address; no proxy is trusted to supply forwarded authority.', 'charter' )
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
			'test'        => 'charter_oauth_public_url',
		);
	}

	/**
	 * Clears current site state during tests or uninstall.
	 *
	 * @since 0.1.0
	 */
	public function delete(): void {
		delete_option( self::OPTION );
	}

	/**
	 * Reads validated persisted state.
	 *
	 * @since 0.1.0
	 *
	 * @return array<string, mixed> Current state record.
	 */
	private function record(): array {
		$record = get_option( self::OPTION, array() );
		if ( ! is_array( $record ) ) {
			return array();
		}

		$normalized = array();
		foreach ( $record as $key => $value ) {
			if ( is_string( $key ) ) {
				$normalized[ $key ] = $value;
			}
		}

		return $normalized;
	}

	/**
	 * Persists one exact lifecycle record and confirms the stored result.
	 *
	 * @since 0.1.0
	 *
	 * @param array<string, mixed> $record Exact record to persist.
	 */
	private function persist( array $record ): bool {
		if ( update_option( self::OPTION, $record, false ) ) {
			return true;
		}

		return $this->record() === $record;
	}

	/**
	 * Records why this site cannot enter Prepared.
	 *
	 * @since 0.1.0
	 *
	 * @param string $error Bounded operator-facing error identifier.
	 */
	private function recordUnavailableError( string $error ): void {
		update_option(
			self::OPTION,
			array(
				'state' => self::AVAILABLE,
				'error' => $error,
			),
			false
		);
	}

	/**
	 * Reports whether explicit local-development mode is enabled.
	 *
	 * @since 0.1.0
	 */
	private static function developmentMode(): bool {
		if ( defined( 'CHARTER_DEVELOPMENT_MODE' ) ) {
			return true === constant( 'CHARTER_DEVELOPMENT_MODE' );
		}

		return function_exists( 'wp_get_environment_type' ) && 'local' === wp_get_environment_type();
	}

	/**
	 * Returns exact additional development HTTP hosts.
	 *
	 * @since 0.1.0
	 *
	 * @return array<string> Configured host names.
	 */
	private static function developmentHosts(): array {
		if ( ! defined( 'CHARTER_DEVELOPMENT_HOSTS' ) ) {
			return array();
		}

		$hosts = constant( 'CHARTER_DEVELOPMENT_HOSTS' );

		return is_array( $hosts ) ? array_values( array_filter( $hosts, 'is_string' ) ) : array();
	}
}
