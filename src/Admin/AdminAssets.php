<?php
/**
 * Gutenberg-powered administrator asset loading.
 *
 * @package GalatanOvidiu\Charter
 */

declare(strict_types=1);

namespace GalatanOvidiu\Charter\Admin;

/**
 * Loads one compiled administrator application on its owning WordPress screen.
 *
 * @since 0.1.0
 */
final class AdminAssets {

	/**
	 * Enqueues one generated JavaScript entry point and its matching stylesheet.
	 *
	 * @param string $entry Stable generated entry-point name.
	 */
	public static function enqueue( string $entry ): void {
		$assetPath  = CHARTER_PATH . 'assets/admin/' . $entry . '.asset.php';
		$scriptPath = CHARTER_PATH . 'assets/admin/' . $entry . '.js';
		if ( ! is_file( $assetPath ) || ! is_file( $scriptPath ) ) {
			return;
		}

		$asset = require $assetPath;
		if (
			! is_array( $asset )
			|| ! is_array( $asset['dependencies'] ?? null )
			|| ! is_string( $asset['version'] ?? null )
		) {
			return;
		}
		foreach ( $asset['dependencies'] as $dependency ) {
			if ( ! is_string( $dependency ) ) {
				return;
			}
		}
		$dependencies = array_values( $asset['dependencies'] );

		$handle = 'charter-' . $entry;
		wp_enqueue_script(
			$handle,
			plugins_url( 'assets/admin/' . $entry . '.js', CHARTER_FILE ),
			$dependencies,
			$asset['version'],
			array( 'in_footer' => true )
		);
		wp_set_script_translations( $handle, 'charter', CHARTER_PATH . 'languages' );

		$stylePath = CHARTER_PATH . 'assets/css/admin.css';
		if ( is_file( $stylePath ) ) {
			wp_enqueue_style(
				'charter-admin',
				plugins_url( 'assets/css/admin.css', CHARTER_FILE ),
				array( 'wp-components' ),
				(string) filemtime( $stylePath )
			);
		}
	}

	/**
	 * Renders safe application bootstrap data without adding a global variable.
	 *
	 * @param string               $id   Unique script element identifier.
	 * @param array<string, mixed> $data Secret-free presentation data.
	 */
	public static function renderData( string $id, array $data ): void {
		$json = wp_json_encode( $data, JSON_HEX_TAG | JSON_HEX_AMP | JSON_HEX_APOS | JSON_HEX_QUOT );
		if ( ! is_string( $json ) ) {
			$json = '{}';
		}
		?>
		<script type="application/json" id="<?php echo esc_attr( $id ); ?>"><?php echo $json; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- wp_json_encode plus all HTML hexadecimal flags makes the JSON safe inside this script element. ?></script>
		<?php
	}
}
