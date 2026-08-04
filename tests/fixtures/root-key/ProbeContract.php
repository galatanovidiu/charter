<?php
/**
 * Side-effect-free contract shared by the Slice 0 root-key probe processes.
 *
 * @package GalatanOvidiu\Charter
 */

declare(strict_types=1);

namespace GalatanOvidiu\Charter\Tests\Fixtures\RootKey;

/**
 * Defines fixed non-secret values shared across isolated probe processes.
 */
final class ProbeContract {

	/**
	 * Known non-secret markers the failure worker must never expose.
	 *
	 * @var list<string>
	 */
	public const FAILURE_OUTPUT_MARKERS = array(
		'charter-slice0-raw-credential-marker',
		'charter-slice0-root-input-marker',
		'charter-slice0-derived-key-marker',
	);
}
