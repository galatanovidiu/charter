<?php
/**
 * Dynamic registration quota failure.
 *
 * @package GalatanOvidiu\Charter
 */

declare(strict_types=1);

namespace GalatanOvidiu\Charter\OAuth;

use RuntimeException;

/**
 * Distinguishes quota exhaustion from invalid registration metadata.
 *
 * @since 0.1.0
 */
final class DynamicRegistrationQuotaException extends RuntimeException {
}
