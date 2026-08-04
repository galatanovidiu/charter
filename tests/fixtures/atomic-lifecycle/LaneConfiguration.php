<?php
/**
 * Private connection and public evidence configuration for one P1 lane.
 *
 * @package GalatanOvidiu\Charter
 */

declare(strict_types=1);

namespace GalatanOvidiu\Charter\Tests\Fixtures\AtomicLifecycle;

// phpcs:disable Generic.Commenting.DocComment.MissingShort, Squiz.Commenting -- Private disposable lane wiring is documented by the constructor and public evidence projection.

use InvalidArgumentException;
use mysqli;
use RuntimeException;

/**
 * Holds one exact disposable lane without exposing connection credentials.
 */
final class LaneConfiguration {

	/**
	 * @param string    $databaseHost              Disposable database host.
	 * @param int       $databasePort              Disposable database port.
	 * @param string    $databaseName              Disposable database name.
	 * @param string    $databaseUser              Disposable database user.
	 * @param string    $databasePassword          Disposable database password.
	 * @param string    $databaseFamily            Expected database family.
	 * @param string    $databaseVersion           Expected exact database version.
	 * @param string    $databaseImageDigest       Resolved local database image digest.
	 * @param string    $isolation                 Requested transaction isolation.
	 * @param bool|null $snapshotIsolation         Expected MariaDB snapshot-isolation value.
	 * @param string    $artifactSha256            Pre-P1 artifact checksum.
	 * @param string    $wordpressVersion          Expected exact WordPress version.
	 * @param string    $wordpressSourceDirectory  Exact mounted WordPress source directory.
	 */
	public function __construct(
		private readonly string $databaseHost,
		private readonly int $databasePort,
		private readonly string $databaseName,
		private readonly string $databaseUser,
		private readonly string $databasePassword,
		private readonly string $databaseFamily,
		private readonly string $databaseVersion,
		private readonly string $databaseImageDigest,
		private readonly string $isolation,
		private readonly ?bool $snapshotIsolation,
		private readonly string $artifactSha256,
		private readonly string $wordpressVersion = HarnessContract::WORDPRESS_VERSION,
		private readonly string $wordpressSourceDirectory = '/wordpress'
	) {
		$this->assertValid();
	}

	/**
	 * Reads the private runner-provisioned configuration.
	 */
	public static function fromEnvironment(): self {
		return new self(
			self::requiredEnvironmentString( 'CHARTER_ATOMIC_DB_HOST' ),
			self::environmentPort( 'CHARTER_ATOMIC_DB_PORT', 3306 ),
			self::requiredEnvironmentString( 'CHARTER_ATOMIC_DB_NAME' ),
			self::requiredEnvironmentString( 'CHARTER_ATOMIC_DB_USER' ),
			self::requiredEnvironmentString( 'CHARTER_ATOMIC_DB_PASSWORD' ),
			self::requiredEnvironmentString( 'CHARTER_ATOMIC_DB_FAMILY' ),
			self::requiredEnvironmentString( 'CHARTER_ATOMIC_DB_VERSION' ),
			self::requiredEnvironmentString( 'CHARTER_ATOMIC_DB_IMAGE_DIGEST' ),
			self::requiredEnvironmentString( 'CHARTER_ATOMIC_ISOLATION' ),
			self::environmentSnapshotIsolation(),
			self::requiredEnvironmentString( 'CHARTER_ATOMIC_ARTIFACT_SHA256' ),
			self::requiredEnvironmentString( 'CHARTER_ATOMIC_WORDPRESS_VERSION' ),
			self::requiredEnvironmentString( 'CHARTER_ATOMIC_WORDPRESS_DIR' )
		);
	}

	/**
	 * Creates a fresh independent connection for one observer or actor.
	 */
	public function connect(): mysqli {
		// phpcs:ignore WordPress.DB.RestrictedFunctions.mysql_mysqli_report -- Independent mysqli connections are the P1 behavior under test.
		mysqli_report( MYSQLI_REPORT_OFF );
		$connection = new mysqli();
		$connected  = $connection->real_connect(
			$this->databaseHost,
			$this->databaseUser,
			$this->databasePassword,
			$this->databaseName,
			$this->databasePort
		);

		if ( ! $connected ) {
			throw new RuntimeException( 'Disposable database connection failed.' );
		}

		$connection->set_charset( 'utf8mb4' );
		$isolationSet = $connection->query(
			'SET SESSION TRANSACTION ISOLATION LEVEL ' . $this->isolation
		);

		if ( true !== $isolationSet ) {
			$connection->close();
			throw new RuntimeException( 'Disposable isolation configuration failed.' );
		}

		return $connection;
	}

	public function databaseFamily(): string {
		return $this->databaseFamily;
	}

	public function databaseVersion(): string {
		return $this->databaseVersion;
	}

	public function databaseImageDigest(): string {
		return $this->databaseImageDigest;
	}

	public function isolation(): string {
		return $this->isolation;
	}

	public function snapshotIsolation(): ?bool {
		return $this->snapshotIsolation;
	}

	public function artifactSha256(): string {
		return $this->artifactSha256;
	}

	public function wordpressVersion(): string {
		return $this->wordpressVersion;
	}

	public function wordpressSourceDirectory(): string {
		return $this->wordpressSourceDirectory;
	}

	/**
	 * Fixed public evidence fields for this lane.
	 *
	 * @return array<string, bool|int|string|null>
	 */
	public function publicEvidence(): array {
		return array(
			'database_family'            => $this->databaseFamily,
			'database_version'           => $this->databaseVersion,
			'database_image_digest'      => $this->databaseImageDigest,
			'artifact_sha256'            => $this->artifactSha256,
			'engine'                     => 'InnoDB',
			'isolation'                  => $this->isolation,
			'mariadb_snapshot_isolation' => $this->snapshotIsolation,
			'sql_mode'                   => '',
			'wordpress_version'          => $this->wordpressVersion,
			'php_version'                => PHP_VERSION,
		);
	}

	private function assertValid(): void {
		if ( ! in_array( $this->databaseFamily, array( 'mysql', 'mariadb' ), true ) ) {
			throw new InvalidArgumentException( 'Unexpected database family.' );
		}

		if ( ! in_array( $this->isolation, array( 'REPEATABLE READ', 'READ COMMITTED' ), true ) ) {
			throw new InvalidArgumentException( 'Unexpected transaction isolation.' );
		}

		if ( ! preg_match( '/^sha256:[a-f0-9]{64}$/D', $this->databaseImageDigest ) ) {
			throw new InvalidArgumentException( 'Invalid database image digest.' );
		}

		if ( ! preg_match( '/^[a-f0-9]{64}$/D', $this->artifactSha256 ) ) {
			throw new InvalidArgumentException( 'Invalid artifact checksum.' );
		}

		if ( HarnessContract::WORDPRESS_VERSION !== $this->wordpressVersion ) {
			throw new InvalidArgumentException( 'Unexpected WordPress version.' );
		}

		if ( '' === $this->databaseHost || '' === $this->databaseName || '' === $this->databaseUser ) {
			throw new InvalidArgumentException( 'Incomplete disposable database configuration.' );
		}

		if ( '' === $this->databasePassword || '' === $this->wordpressSourceDirectory ) {
			throw new InvalidArgumentException( 'Incomplete private harness configuration.' );
		}
	}

	private static function requiredEnvironmentString( string $name ): string {
		$value = getenv( $name );

		if ( false === $value || '' === $value ) {
			throw new InvalidArgumentException( 'Required harness environment is absent.' );
		}

		return $value;
	}

	private static function environmentPort( string $name, int $fallback ): int {
		$value = getenv( $name );

		if ( false === $value || '' === $value ) {
			return $fallback;
		}

		if ( ! ctype_digit( $value ) || 1 > (int) $value || 65535 < (int) $value ) {
			throw new InvalidArgumentException( 'Invalid disposable database port.' );
		}

		return (int) $value;
	}

	private static function environmentSnapshotIsolation(): ?bool {
		$value = self::requiredEnvironmentString( 'CHARTER_ATOMIC_SNAPSHOT_ISOLATION' );

		return match ( $value ) {
			'null' => null,
			'0'    => false,
			'1'    => true,
			default => throw new InvalidArgumentException( 'Invalid snapshot-isolation evidence.' ),
		};
	}
}
