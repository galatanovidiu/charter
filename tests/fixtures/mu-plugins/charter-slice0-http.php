<?php
/**
 * Boots the disposable Slice 0 HTTP adapter in wp-env only.
 *
 * @package GalatanOvidiu\Charter
 */

declare(strict_types=1);

use GalatanOvidiu\Charter\Tests\Prototype\Multisite\DiscoveryHttpAdapter;
use GalatanOvidiu\Charter\Tests\Prototype\Multisite\OperationProbeHttpAdapter;
use GalatanOvidiu\Charter\Tests\Prototype\DiscoveryPublication\UnsupportedTopologyDiagnostics;

$charterSlice0Root = dirname( WPMU_PLUGIN_DIR ) . '/plugins/charter';

require_once $charterSlice0Root . '/vendor/autoload.php';

DiscoveryHttpAdapter::register();
OperationProbeHttpAdapter::register();
UnsupportedTopologyDiagnostics::register();
