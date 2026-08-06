<?php
/**
 * Resets only focused real-HTTP OAuth test state.
 *
 * @package GalatanOvidiu\Charter
 */

use GalatanOvidiu\Charter\Plugin;
use GalatanOvidiu\Charter\Schema;

$charterHttpPlugin = Plugin::boot();
Schema::install();
$charterHttpPlugin->credentials()->deleteAll();
$charterHttpPlugin->clients()->deleteAll();
$charterHttpPlugin->siteState()->delete();
delete_option( 'charter_http_disable_mcp_profile' );

if ( ! $charterHttpPlugin->siteState()->prepareCurrentSite() ) {
	throw new RuntimeException( 'The focused HTTP issuer could not be reset to Prepared.' );
}
