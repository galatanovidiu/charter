<?php
/**
 * Disposable Slice 0 sanitized transition failure.
 *
 * @package GalatanOvidiu\Charter
 */

declare(strict_types=1);

namespace GalatanOvidiu\Charter\Tests\Prototype\AtomicLifecycle;

use RuntimeException;

/**
 * Carries only fixed classifications and numeric database diagnostics.
 *
 * @since 0.1.0
 */
final class TransitionFailure extends RuntimeException {

	public const DEADLOCK = 'deadlock';

	public const LOCK_TIMEOUT = 'lock_timeout';

	public const CONNECTION_LOST = 'connection_lost';

	public const QUERY_ERROR = 'query_error';

	public const INJECTED = 'injected';

	/**
	 * Creates one sanitized transition failure.
	 *
	 * @param string      $classification Fixed failure classification.
	 * @param int|null    $databaseErrorNumber Numeric database error number.
	 * @param string|null $sqlStateClass Two-character SQLSTATE class.
	 * @param int|null    $connectionId Numeric proof connection identifier.
	 */
	public function __construct(
		private readonly string $classification,
		private readonly ?int $databaseErrorNumber = null,
		private readonly ?string $sqlStateClass = null,
		private readonly ?int $connectionId = null
	) {
		parent::__construct( $classification );
	}

	/**
	 * Creates a fixed injected-failure result.
	 *
	 * @param int|null $connectionId Numeric proof connection identifier.
	 */
	public static function injected( ?int $connectionId = null ): self {
		return new self( self::INJECTED, null, null, $connectionId );
	}

	/**
	 * Returns the fixed failure classification.
	 */
	public function classification(): string {
		return $this->classification;
	}

	/**
	 * Returns the numeric database error number, when available.
	 */
	public function databaseErrorNumber(): ?int {
		return $this->databaseErrorNumber;
	}

	/**
	 * Returns the two-character SQLSTATE class, when available.
	 */
	public function sqlStateClass(): ?string {
		return $this->sqlStateClass;
	}

	/**
	 * Returns the sanitized connection identifier, when known.
	 */
	public function connectionId(): ?int {
		return $this->connectionId;
	}
}
