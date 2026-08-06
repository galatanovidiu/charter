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
if ( 'verify_deleted' === $charterNetworkAction ) {
	global $wpdb;

	$charterNetworkExistingTables = 0;
	foreach ( Schema::tablesForSite( $charterNetworkSiteId ) as $charterNetworkTable ) {
		$charterNetworkExistingTables += $charterNetworkTable === $wpdb->get_var( $wpdb->prepare( 'SHOW TABLES LIKE %s', $wpdb->esc_like( $charterNetworkTable ) ) ) ? 1 : 0; // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching -- Disposable real-database lifecycle assertion.
	}
	$charterNetworkMetaKey = $wpdb->get_blog_prefix( $charterNetworkSiteId ) . 'charter_oauth_revocation_notice_cursor';
	$charterNetworkCursors = (int) $wpdb->get_var( $wpdb->prepare( "SELECT COUNT(*) FROM {$wpdb->usermeta} WHERE meta_key = %s", $charterNetworkMetaKey ) ); // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching,WordPress.DB.PreparedSQL.InterpolatedNotPrepared -- Disposable non-secret lifecycle assertion.
	$charterNetworkOptions = 0;
	$charterNetworkCron    = 0;
	if ( null !== $charterNetworkSite ) {
		switch_to_blog( $charterNetworkSiteId );
		try {
			$charterNetworkOwnedOptions = array(
				'charter_oauth_schema_version',
				'charter_oauth_site_state',
				'charter_oauth_dcr_enabled',
				'charter_oauth_emergency_mode',
				'charter_oauth_cleanup_status',
				'charter_oauth_signing_key_guard',
			);
			foreach ( $charterNetworkOwnedOptions as $charterNetworkOwnedOption ) {
				$charterNetworkOptions += false === get_option( $charterNetworkOwnedOption, false ) ? 0 : 1;
			}
			$charterNetworkCron = false === wp_next_scheduled( 'charter_oauth_daily_cleanup' ) ? 0 : 1;
		} finally {
			restore_current_blog();
		}
	}

	echo 'CHARTER_NETWORK_RESULT=' . wp_json_encode(
		array(
			'site_exists'  => null === $charterNetworkSite ? 0 : 1,
			'table_count'  => $charterNetworkExistingTables,
			'cursor_count' => $charterNetworkCursors,
			'option_count' => $charterNetworkOptions,
			'cron_count'   => $charterNetworkCron,
		)
	) . "\n";

	return;
}

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
	if ( 'seed_deletion' === $charterNetworkAction ) {
		Schema::install();
		update_option( 'charter_oauth_dcr_enabled', '0', false );
		update_user_option( 1, 'charter_oauth_revocation_notice_cursor', array( 'grant_id' => 1 ) );
		wp_schedule_event( time() + HOUR_IN_SECONDS, 'daily', 'charter_oauth_daily_cleanup', array( 'daily' ), true );
	}

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
