<?php
/**
 * Plugin composition root.
 *
 * @package GalatanOvidiu\Charter
 */

declare(strict_types=1);

namespace GalatanOvidiu\Charter;

/**
 * Coordinates Charter's feature modules.
 *
 * Feature modules register their hooks here when their implementations exist.
 *
 * @since 0.1.0
 */
final class Plugin {

	/**
	 * Current plugin instance.
	 *
	 * @since 0.1.0
	 *
	 * @var self|null
	 */
	private static ?self $instance = null;

	/**
	 * Prevents direct construction.
	 *
	 * @since 0.1.0
	 */
	private function __construct() {
	}

	/**
	 * Boots the plugin once and returns its composition root.
	 *
	 * @since 0.1.0
	 *
	 * @return self The plugin composition root.
	 */
	public static function boot(): self {
		if ( null === self::$instance ) {
			self::$instance = new self();
		}

		return self::$instance;
	}
}
