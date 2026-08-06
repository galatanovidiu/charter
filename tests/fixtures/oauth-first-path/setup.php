<?php
/**
 * Prepares deterministic real-HTTP OAuth test state.
 *
 * @package GalatanOvidiu\Charter
 */

use GalatanOvidiu\Charter\Plugin;

$charterHttpPlugin = Plugin::boot();
$charterHttpState  = $charterHttpPlugin->siteState();

if ( null === $charterHttpState->identity() ) {
	$charterHttpState->prepareCurrentSite();
}

$charterHttpIdentity = $charterHttpState->identity();
if ( null === $charterHttpIdentity ) {
	throw new RuntimeException( 'The focused HTTP issuer could not be prepared.' );
}

if ( ! $charterHttpState->isEnabled() ) {
	if (
		! $charterHttpState->recordDiscoveryVerification( $charterHttpIdentity->issuer() )
		|| ! $charterHttpState->enable( $charterHttpIdentity->issuer() )
	) {
		throw new RuntimeException( 'The focused HTTP issuer could not be enabled.' );
	}
}

$charterHttpPlugin->clients()->registerPublicClient(
	$charterHttpIdentity->issuer(),
	'charter-http-client',
	'Charter HTTP client',
	array( 'https://client.example.test/callback' )
);

$charterHttpPlugin->clients()->registerPublicClient(
	$charterHttpIdentity->issuer(),
	'charter-http-mcp-client',
	'Charter HTTP MCP client',
	array( 'https://mcp-client.example.test/callback' ),
	true
);

$charterHttpUser = get_user_by( 'login', 'charter-oauth-user' );
if ( false === $charterHttpUser ) {
	$charterHttpUserId = wp_create_user( 'charter-oauth-user', 'charter-http-password', 'charter-oauth-user@example.test' );
	if ( is_wp_error( $charterHttpUserId ) ) {
		throw new RuntimeException( 'The focused HTTP user could not be created.' );
	}
	$charterHttpUser = get_userdata( $charterHttpUserId );
}

if ( false === $charterHttpUser ) {
	throw new RuntimeException( 'The focused HTTP user could not be loaded.' );
}

wp_set_password( 'charter-http-password', $charterHttpUser->ID );
( new WP_User( $charterHttpUser->ID ) )->set_role( 'subscriber' );
