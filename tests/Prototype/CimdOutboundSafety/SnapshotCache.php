<?php
/**
 * Disposable CIMD authoritative-snapshot cache.
 *
 * @package GalatanOvidiu\Charter
 */

declare(strict_types=1);

namespace GalatanOvidiu\Charter\Tests\Prototype\CimdOutboundSafety;

/**
 * Separates reusable redirect authority from body-free stale diagnostics.
 *
 * @since 0.1.0
 */
final class SnapshotCache {

	/**
	 * Reusable authoritative snapshots keyed by exact Client Identifier.
	 *
	 * @var array<string, array{redirects:list<string>, fingerprint:string, fresh_until:int}>
	 */
	private array $authoritative = array();

	/**
	 * Body-free diagnostics keyed by exact Client Identifier.
	 *
	 * @var array<string, array{fingerprint:string, classification:string, observed_at:int}>
	 */
	private array $diagnostics = array();

	/**
	 * Stores one reusable authoritative snapshot and replaces any diagnostic.
	 *
	 * @param string   $clientId   Exact Client Identifier.
	 * @param string[] $redirects  Exact validated redirects.
	 * @param string   $fingerprint Document fingerprint.
	 * @param int      $freshUntil Exclusive freshness boundary.
	 * @phpstan-param list<string> $redirects
	 */
	public function storeAuthoritative(
		string $clientId,
		array $redirects,
		string $fingerprint,
		int $freshUntil
	): void {
		$this->authoritative[ $clientId ] = array(
			'redirects'   => $redirects,
			'fingerprint' => $fingerprint,
			'fresh_until' => $freshUntil,
		);
		unset( $this->diagnostics[ $clientId ] );
	}

	/**
	 * Returns one fresh snapshot, retiring stale redirect authority first.
	 *
	 * @param string $clientId Exact Client Identifier.
	 * @param int    $now      Current wall-clock second.
	 * @return array{redirects:list<string>, fingerprint:string, fresh_until:int}|null Fresh snapshot.
	 */
	public function fresh( string $clientId, int $now ): ?array {
		$snapshot = $this->authoritative[ $clientId ] ?? null;
		if ( null === $snapshot ) {
			return null;
		}

		if ( $now < $snapshot['fresh_until'] ) {
			return $snapshot;
		}

		unset( $this->authoritative[ $clientId ] );
		$this->diagnostics[ $clientId ] = array(
			'fingerprint'    => $snapshot['fingerprint'],
			'classification' => 'stale',
			'observed_at'    => $now,
		);

		return null;
	}

	/**
	 * Reports whether reusable redirect authority currently exists.
	 *
	 * @param string $clientId Exact Client Identifier.
	 */
	public function hasAuthoritative( string $clientId ): bool {
		return isset( $this->authoritative[ $clientId ] );
	}

	/**
	 * Stores only the fields permitted for a stale diagnostic.
	 *
	 * @param string $clientId       Exact Client Identifier.
	 * @param string $fingerprint    Non-secret document fingerprint.
	 * @param string $classification Stable diagnostic classification.
	 * @param int    $observedAt     Observation wall-clock second.
	 */
	public function storeDiagnostic(
		string $clientId,
		string $fingerprint,
		string $classification,
		int $observedAt
	): void {
		unset( $this->authoritative[ $clientId ] );
		$this->diagnostics[ $clientId ] = array(
			'fingerprint'    => $fingerprint,
			'classification' => $classification,
			'observed_at'    => $observedAt,
		);
	}

	/**
	 * Removes all snapshot and diagnostic state for one identity.
	 *
	 * @param string $clientId Exact Client Identifier.
	 */
	public function clear( string $clientId ): void {
		unset( $this->authoritative[ $clientId ], $this->diagnostics[ $clientId ] );
	}

	/**
	 * Returns a sanitized state observation without redirect values or bodies.
	 *
	 * @param string $clientId Exact Client Identifier.
	 * @return array{classification:string, redirect_count:int, fingerprint:string, fresh_until:int} Observation.
	 */
	public function observation( string $clientId ): array {
		$snapshot = $this->authoritative[ $clientId ] ?? null;
		if ( null !== $snapshot ) {
			return array(
				'classification' => 'authoritative',
				'redirect_count' => count( $snapshot['redirects'] ),
				'fingerprint'    => $snapshot['fingerprint'],
				'fresh_until'    => $snapshot['fresh_until'],
			);
		}

		$diagnostic = $this->diagnostics[ $clientId ] ?? null;
		if ( null !== $diagnostic ) {
			return array(
				'classification' => 'diagnostic',
				'redirect_count' => 0,
				'fingerprint'    => $diagnostic['fingerprint'],
				'fresh_until'    => 0,
			);
		}

		return array(
			'classification' => 'absent',
			'redirect_count' => 0,
			'fingerprint'    => 'none',
			'fresh_until'    => 0,
		);
	}
}
