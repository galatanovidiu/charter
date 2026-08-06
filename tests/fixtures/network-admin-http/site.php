<?php
/**
 * Operates only the selected disposable Network Admin HTTP fixture site.
 *
 * @package GalatanOvidiu\Charter
 */

use GalatanOvidiu\Charter\OAuth\AuthorizationRequest;
use GalatanOvidiu\Charter\OAuth\Client;
use GalatanOvidiu\Charter\OAuth\CredentialStore;
use GalatanOvidiu\Charter\Plugin;
use GalatanOvidiu\Charter\Schema;

$charterNetworkSiteId = filter_var( getenv( 'CHARTER_NETWORK_SITE_ID' ), FILTER_VALIDATE_INT );
$charterNetworkAction = getenv( 'CHARTER_NETWORK_FIXTURE_ACTION' );

if ( ! is_int( $charterNetworkSiteId ) || $charterNetworkSiteId <= 0 || ! is_string( $charterNetworkAction ) ) {
	throw new RuntimeException( 'The selected Network Admin HTTP fixture is invalid.' );
}

$charterNetworkSite = get_site( $charterNetworkSiteId );
if ( null === $charterNetworkSite ) {
	throw new RuntimeException( 'The selected Network Admin HTTP fixture site does not exist.' );
}

if ( 'map' === $charterNetworkAction ) {
	$charterNetworkUpdated = wp_update_site(
		$charterNetworkSiteId,
		array(
			'domain' => '127.0.0.1:8891',
			'path'   => '/',
		)
	);
	if ( is_wp_error( $charterNetworkUpdated ) ) {
		throw new RuntimeException( 'The selected Network Admin HTTP fixture site could not be mapped.' );
	}
}

switch_to_blog( $charterNetworkSiteId );
try {
	if ( 'map' === $charterNetworkAction ) {
		update_option( 'home', 'http://127.0.0.1:8891' );
		update_option( 'siteurl', 'http://127.0.0.1:8891' );
	}

	$charterNetworkPlugin   = Plugin::boot();
	$charterNetworkState    = $charterNetworkPlugin->siteState();
	$charterNetworkIdentity = $charterNetworkState->identity();

	if ( 'create_grants' === $charterNetworkAction ) {
		if ( null === $charterNetworkIdentity || ! $charterNetworkState->isEnabled() || ! Schema::isInstalled() ) {
			throw new RuntimeException( 'The selected Network Admin HTTP fixture issuer is not enabled.' );
		}

		$charterNetworkStore = $charterNetworkPlugin->credentials();
		foreach ( array( 'first', 'second' ) as $charterNetworkLabel ) {
			$charterNetworkClientId = 'charter-network-http-' . $charterNetworkLabel;
			$charterNetworkClient   = new Client(
				$charterNetworkIdentity->issuer(),
				$charterNetworkClientId,
				$charterNetworkClientId,
				array( 'https://' . $charterNetworkClientId . '.example.test/callback' )
			);
			$charterNetworkRequest  = new AuthorizationRequest(
				$charterNetworkIdentity->issuer(),
				$charterNetworkIdentity->issuer(),
				$charterNetworkClient,
				$charterNetworkClient->redirectUris()[0],
				'wordpress:access', // phpcs:ignore WordPress.WP.CapitalPDangit.MisspelledInText -- Exact OAuth scope token.
				str_repeat( 'a', 43 ),
				null
			);
			$charterNetworkNow      = time();
			$charterNetworkToken    = $charterNetworkStore->issueAuthorizationRequest( $charterNetworkRequest, 1, $charterNetworkNow );
			$charterNetworkRecord   = $charterNetworkStore->find( CredentialStore::AUTHORIZATION_REQUEST, $charterNetworkIdentity->issuer(), $charterNetworkToken );
			if ( null === $charterNetworkRecord || ! is_string( $charterNetworkStore->approveAuthorization( $charterNetworkRecord, $charterNetworkNow + 1 ) ) ) {
				throw new RuntimeException( 'A selected-site Network Admin HTTP grant could not be created.' );
			}
		}
	}

	$charterNetworkIdentity = $charterNetworkState->identity();
	$charterNetworkCount    = 0;
	$charterNetworkReasons  = array();
	if ( null !== $charterNetworkIdentity && Schema::isInstalled() ) {
		$charterNetworkCount   = $charterNetworkPlugin->credentials()->countActiveGrantsForIssuer( $charterNetworkIdentity->issuer() );
		$charterNetworkReasons = array_map(
			static fn ( $event ): string => $event->reason(),
			$charterNetworkPlugin->audit()->listForIssuer( $charterNetworkIdentity->issuer(), 50 )
		);
	}

	echo 'CHARTER_NETWORK_RESULT=' . wp_json_encode(
		array(
			'state'            => $charterNetworkState->state(),
			'issuer'           => null === $charterNetworkIdentity ? null : $charterNetworkIdentity->issuer(),
			'containment_mode' => $charterNetworkPlugin->containment()->mode(),
			'active_grants'    => $charterNetworkCount,
			'audit_reasons'    => $charterNetworkReasons,
		),
		JSON_UNESCAPED_SLASHES
	) . "\n";
} finally {
	restore_current_blog();
}
