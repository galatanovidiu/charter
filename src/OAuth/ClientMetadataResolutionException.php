<?php
/**
 * Sanitized CIMD resolution failure.
 *
 * @package GalatanOvidiu\Charter
 */

declare(strict_types=1);

namespace GalatanOvidiu\Charter\OAuth;

use RuntimeException;

/** Prevents untrusted URL, DNS, transport, or body values entering errors. */
final class ClientMetadataResolutionException extends RuntimeException {

	/**
	 * Creates a sanitized resolution failure.
	 *
	 * @param string $classification Stable internal failure class.
	 */
	public function __construct( private readonly string $classification ) {
		parent::__construct( 'charter_cimd_unavailable' );
	}

	/** Returns the stable internal failure class. */
	public function classification(): string {
		return $this->classification;
	}
}
