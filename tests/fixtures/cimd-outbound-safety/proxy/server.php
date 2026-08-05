<?php
/**
 * Boots one disposable non-forwarding proxy observation sink.
 *
 * @package GalatanOvidiu\Charter
 */

declare(strict_types=1);

require dirname( __DIR__ ) . '/state.php';

charter_p3_proxy_main( (string) ( $argv[1] ?? 'http' ) );
