<?php
/**
 * Disposable Slice 0 per-issuer verification ledger.
 *
 * @package GalatanOvidiu\Charter
 */

declare(strict_types=1);

namespace GalatanOvidiu\Charter\Tests\Prototype\DiscoveryPublication;

/**
 * Records exact external observations without performing reachability probes.
 *
 * @since 0.1.0
 */
final class VerificationLedger {

	/**
	 * Available state.
	 *
	 * @var string
	 */
	public const AVAILABLE = 'available';

	/**
	 * Prepared state.
	 *
	 * @var string
	 */
	public const PREPARED = 'prepared';

	/**
	 * Enabled state.
	 *
	 * @var string
	 */
	public const ENABLED = 'enabled';

	/**
	 * Exact proof records keyed by issuer.
	 *
	 * @since 0.1.0
	 *
	 * @var array<string, array{
	 *     state: string,
	 *     expected: array<string, string>,
	 *     verification?: array{method: string, result: string}
	 * }>
	 */
	private array $records = array();

	/**
	 * Prepares one exact issuer and its required metadata observations.
	 *
	 * @since 0.1.0
	 *
	 * @param string $issuer    The exact issuer.
	 * @param array  $resources The isolated resources.
	 */
	public function prepare( string $issuer, array $resources = array() ): void {
		$expected = array(
			MetadataProjector::authorizationServerUrl( $issuer )            => $issuer,
			MetadataProjector::protectedResourceUrl( $issuer, $issuer )      => $issuer,
		);

		foreach ( $resources as $resource ) {
			$expected[ MetadataProjector::protectedResourceUrl( $issuer, $resource ) ] = $resource;
		}

		$this->records[ $issuer ] = array(
			'state'    => self::PREPARED,
			'expected' => $expected,
		);
	}

	/**
	 * Records a complete successful external observation for one issuer.
	 *
	 * @since 0.1.0
	 *
	 * @param string                               $issuer       The exact issuer.
	 * @param string                               $method       The external method.
	 * @param list<array<string, bool|int|string>> $observations The fixed-schema validator results.
	 * @return bool Whether the exact verification was recorded.
	 */
	public function recordVerification( string $issuer, string $method, array $observations ): bool {
		if (
			! isset( $this->records[ $issuer ] )
			|| self::PREPARED !== $this->records[ $issuer ]['state']
			|| ! in_array( $method, array( 'browser', 'curl', 'real_client' ), true )
		) {
			return false;
		}

		$expected = $this->records[ $issuer ]['expected'];
		$seen     = array();

		foreach ( $observations as $observation ) {
			$url = $observation['requested_url'] ?? null;

			if (
				! is_string( $url )
				|| ! isset( $expected[ $url ] )
				|| isset( $seen[ $url ] )
				|| ! $this->isAcceptedObservation( $observation )
			) {
				return false;
			}

			$seen[ $url ] = true;
		}

		if ( count( $seen ) !== count( $expected ) ) {
			return false;
		}

		$this->records[ $issuer ]['verification'] = array(
			'method' => $method,
			'result' => 'passed',
		);

		return true;
	}

	/**
	 * Enables only an exact issuer with a successful recorded verification.
	 *
	 * @since 0.1.0
	 *
	 * @param string $issuer The exact issuer.
	 * @return bool Whether the issuer was enabled.
	 */
	public function enable( string $issuer ): bool {
		if ( 'passed' !== ( $this->records[ $issuer ]['verification']['result'] ?? null ) ) {
			return false;
		}

		$this->records[ $issuer ]['state'] = self::ENABLED;

		return true;
	}

	/**
	 * Returns one exact issuer state.
	 *
	 * @since 0.1.0
	 *
	 * @param string $issuer The exact issuer.
	 * @return string The issuer state.
	 */
	public function stateFor( string $issuer ): string {
		return $this->records[ $issuer ]['state'] ?? self::AVAILABLE;
	}

	/**
	 * Returns the fixed per-issuer method/result record.
	 *
	 * @since 0.1.0
	 *
	 * @param string $issuer The exact issuer.
	 * @return array{method: string, result: string}|null The record, if verified.
	 */
	public function verificationFor( string $issuer ): ?array {
		return $this->records[ $issuer ]['verification'] ?? null;
	}

	/**
	 * Confirms one observation is an exact accepted validator result.
	 *
	 * @since 0.1.0
	 *
	 * @param array<string, bool|int|string> $observation The fixed-schema validator result.
	 * @return bool Whether every exact boundary passed.
	 */
	private function isAcceptedObservation( array $observation ): bool {
		return 200 === ( $observation['status'] ?? null )
			&& true === ( $observation['status_match'] ?? null )
			&& 'application/json' === ( $observation['content_type_class'] ?? null )
			&& 'json' === ( $observation['body_class'] ?? null )
			&& false === ( $observation['redirect_present'] ?? null )
			&& true === ( $observation['identity_match'] ?? null )
			&& true === ( $observation['metadata_match'] ?? null )
			&& '*' === ( $observation['access_control_allow_origin'] ?? null )
			&& false === ( $observation['access_control_credentials_present'] ?? null )
			&& 'no-store' === ( $observation['cache_class'] ?? null )
			&& true === ( $observation['canonical_location_match'] ?? null )
			&& true === ( $observation['front_controller_reached_match'] ?? null )
			&& true === ( $observation['wordpress_tree_version_match'] ?? null )
			&& false === ( $observation['backend_reference_present'] ?? null )
			&& true === ( $observation['verification_accepted'] ?? null );
	}
}
