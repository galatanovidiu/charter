<?php
/**
 * Boots one disposable TLS origin or observation sink.
 *
 * @package GalatanOvidiu\Charter
 */

declare(strict_types=1);

require dirname( __DIR__ ) . '/state.php';

charter_p3_origin_main( (string) ( $argv[1] ?? 'origin' ) );
