<?php
/**
 * Dynamic Client Registration policy and lifecycle.
 *
 * @package GalatanOvidiu\Charter
 */

declare(strict_types=1);

namespace GalatanOvidiu\Charter\OAuth;

use GalatanOvidiu\Charter\Security\AuditLog;
use GalatanOvidiu\Charter\Security\RateLimiter;
use GalatanOvidiu\Charter\Security\SourceAddress;
use GalatanOvidiu\Charter\Site\SiteState;
use InvalidArgumentException;
use RuntimeException;

/**
 * Applies operational state, abuse controls, quotas, and immutable registration.
 *
 * @since 0.1.0
 */
final class DynamicRegistrationService {

	private const ENABLED_OPTION = 'charter_oauth_dcr_enabled';

	private const DEFAULT_POLICY = array(
		'network_ten_minutes' => 5,
		'network_day'         => 20,
		'issuer_day'          => 100,
	);

	/**
	 * Creates the registration service.
	 *
	 * @param SiteState            $siteState Site lifecycle.
	 * @param ClientRegistry       $clients Client registry.
	 * @param RateLimiter          $rateLimiter Abuse counters.
	 * @param AuditLog             $audit Security ledger.
	 * @param EmergencyContainment $containment Issuer-local emergency mode.
	 */
	public function __construct(
		private readonly SiteState $siteState,
		private readonly ClientRegistry $clients,
		private readonly RateLimiter $rateLimiter,
		private readonly AuditLog $audit,
		private readonly EmergencyContainment $containment
	) {
	}

	/**
	 * Reports whether new dynamic registrations are enabled by operator policy.
	 */
	public static function isEnabled(): bool {
		return '0' !== get_option( self::ENABLED_OPTION, '1' );
	}

	/**
	 * Changes only the new-registration policy.
	 *
	 * @param bool $enabled Whether new registrations are accepted.
	 */
	public static function setEnabled( bool $enabled ): bool {
		$stored = $enabled ? '1' : '0';
		if ( update_option( self::ENABLED_OPTION, $stored, false ) ) {
			return true;
		}

		return get_option( self::ENABLED_OPTION, '1' ) === $stored;
	}

	/**
	 * Registers one bounded public or confidential client.
	 *
	 * @param string $body Complete JSON registration body.
	 * @return array{client:Client,client_secret:string|null,issued_at:int}
	 * @throws DynamicRegistrationException On protocol or policy failure.
	 */
	public function register( string $body ): array {
		$identity = $this->siteState->identity();
		if ( null === $identity || ! $this->siteState->isEnabled() || ! $this->siteState->requestMatchesIdentity() ) {
			throw new DynamicRegistrationException( 'temporarily_unavailable', 'Dynamic registration is unavailable.', 503 );
		}
		if ( ! $this->containment->issuanceAllowed() ) {
			throw new DynamicRegistrationException( 'temporarily_unavailable', 'Dynamic registration is temporarily unavailable.', 503 );
		}
		if ( ! self::isEnabled() ) {
			throw new DynamicRegistrationException( 'temporarily_unavailable', 'New dynamic registrations are disabled.', 403 );
		}

		$issuer    = $identity->issuer();
		$source    = SourceAddress::current();
		$timestamp = time();
		$this->enforceRateLimits( $issuer, $source, $timestamp );

		try {
			$request = DynamicRegistrationValidator::validate( $body );
		} catch ( InvalidArgumentException $exception ) {
			$error = 'charter_dcr_redirect_invalid' === $exception->getMessage() ? 'invalid_redirect_uri' : 'invalid_client_metadata';
			throw new DynamicRegistrationException( $error, 'The client registration metadata is invalid.', 400 ); // phpcs:ignore WordPress.Security.EscapeOutput.ExceptionNotEscaped -- Error is selected from two fixed protocol constants.
		}

		try {
			$registered = $this->clients->registerDynamicClient(
				$issuer,
				$request->name(),
				$request->redirectUris(),
				$request->authenticationMethod(),
				$request->supportsRefresh(),
				$timestamp
			);
		} catch ( DynamicRegistrationQuotaException ) {
			$this->audit->record( $issuer, 'dcr_quota_exhausted', 'blocked', 'never_authorized_ceiling', null, null, null, $source, $timestamp );
			throw new DynamicRegistrationException( 'temporarily_unavailable', 'The dynamic registration quota is exhausted.', 429, DAY_IN_SECONDS ); // phpcs:ignore WordPress.Security.EscapeOutput.ExceptionNotEscaped -- Typed protocol retry metadata is not rendered here.
		} catch ( InvalidArgumentException ) {
			throw new DynamicRegistrationException( 'invalid_client_metadata', 'The client registration metadata is invalid.', 400 );
		} catch ( RuntimeException ) {
			throw new DynamicRegistrationException( 'temporarily_unavailable', 'The client registration could not be saved.', 503 );
		}

		$this->audit->record( $issuer, 'client_registered', 'success', 'dynamic_registration', null, null, $registered['client']->clientId(), null, $timestamp );

		return array(
			'client'        => $registered['client'],
			'client_secret' => $registered['client_secret'],
			'issued_at'     => $timestamp,
		);
	}

	/**
	 * Applies the three accepted DCR counters.
	 *
	 * @param string $issuer Exact issuer.
	 * @param string $source Normalized source.
	 * @param int    $timestamp Current timestamp.
	 * @throws DynamicRegistrationException When policy denies the request.
	 */
	private function enforceRateLimits( string $issuer, string $source, int $timestamp ): void {
		$policy = apply_filters( 'charter_oauth_rate_limit_policy', self::DEFAULT_POLICY, $issuer ); // phpcs:ignore WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedHooknameFound -- Public advanced operator policy hook.
		if ( ! is_array( $policy ) ) {
			throw new DynamicRegistrationException( 'temporarily_unavailable', 'Dynamic registration policy is invalid.', 503 );
		}

		$checks = array(
			array( 'dcr_network_10m', $source, $policy['network_ten_minutes'] ?? null, 10 * MINUTE_IN_SECONDS ),
			array( 'dcr_network_day', $source, $policy['network_day'] ?? null, DAY_IN_SECONDS ),
			array( 'dcr_issuer_day', 'issuer', $policy['issuer_day'] ?? null, DAY_IN_SECONDS ),
		);
		foreach ( $checks as $check ) {
			if ( ! is_int( $check[2] ) || 1 > $check[2] ) {
				throw new DynamicRegistrationException( 'temporarily_unavailable', 'Dynamic registration policy is invalid.', 503 );
			}
			$decision = $this->rateLimiter->consume( $issuer, $check[0], $check[1], $check[2], $check[3], $timestamp );
			if ( $decision->allowed() ) {
				continue;
			}
			if ( $decision->count() === $decision->limit() + 1 ) {
				$this->audit->record( $issuer, 'rate_limit_escalated', 'blocked', $check[0], null, null, null, $source, $timestamp );
			}
			throw new DynamicRegistrationException( 'temporarily_unavailable', 'Too many dynamic registration requests.', 429, $decision->retryAfter() ); // phpcs:ignore WordPress.Security.EscapeOutput.ExceptionNotEscaped -- Typed protocol retry metadata is not rendered here.
		}
	}
}
