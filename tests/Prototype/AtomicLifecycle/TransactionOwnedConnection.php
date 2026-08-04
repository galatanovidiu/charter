<?php
/**
 * Disposable Slice 0 transaction-owned database connection.
 *
 * @package GalatanOvidiu\Charter
 */

declare(strict_types=1);

namespace GalatanOvidiu\Charter\Tests\Prototype\AtomicLifecycle;

// phpcs:disable WordPress.Security.EscapeOutput.ExceptionNotEscaped -- This proof throws sanitized exception objects and never renders them.

use LogicException;
use mysqli;
use mysqli_result;
use mysqli_sql_exception;
use Throwable;

/**
 * Prevents a failed or reconnected session from resuming one transaction.
 *
 * @since 0.1.0
 */
final class TransactionOwnedConnection {

	/**
	 * Whether one transaction currently owns the connection.
	 *
	 * @var bool
	 */
	private bool $transactionActive = false;

	/**
	 * Whether the current transaction must never resume.
	 *
	 * @var bool
	 */
	private bool $transactionFailed = false;

	/**
	 * Physical connection identifier captured before the transaction began.
	 *
	 * @var int|null
	 */
	private ?int $transactionConnectionId = null;

	/**
	 * Creates one transaction owner for a real physical connection.
	 *
	 * @param mysqli $database Disposable database connection.
	 */
	public function __construct( private readonly mysqli $database ) {
	}

	/**
	 * Returns the current physical database connection identifier.
	 *
	 * @throws TransitionFailure When the connection is unavailable.
	 */
	public function connectionId(): int {
		try {
			$result = $this->database->query( 'SELECT CONNECTION_ID() AS connection_id' );
		} catch ( mysqli_sql_exception $exception ) {
			// phpcs:ignore WordPress.Security.EscapeOutput.ExceptionNotEscaped -- Throws a sanitized classification, never the database message.
			throw $this->databaseFailure( $exception );
		}

		if ( ! $result instanceof mysqli_result ) {
			throw $this->databaseFailure();
		}

		$row = $result->fetch_assoc();
		$result->free();

		if ( ! is_array( $row ) || ! is_numeric( $row['connection_id'] ?? null ) ) {
			// phpcs:ignore WordPress.Security.EscapeOutput.ExceptionNotEscaped -- The fixed exception contains no output-derived material.
			throw new TransitionFailure( TransitionFailure::QUERY_ERROR );
		}

		return (int) $row['connection_id'];
	}

	/**
	 * Runs one complete transaction and rolls back every failed attempt.
	 *
	 * @template T
	 * @param callable(self): T      $work Complete transaction callback.
	 * @param TransitionControl|null $control Optional commit checkpoint control.
	 * @return T
	 * @throws LogicException When another transaction already owns the connection.
	 * @throws TransitionFailure When a database or injected failure prevents commit.
	 */
	public function run( callable $work, ?TransitionControl $control = null ): mixed {
		if ( $this->transactionActive ) {
			throw new LogicException( 'Nested disposable proof transactions are not supported.' );
		}

		$this->transactionConnectionId = $this->connectionId();
		$this->transactionFailed       = false;

		try {
			if ( ! $this->database->begin_transaction() ) {
				throw $this->databaseFailure();
			}

			$this->transactionActive = true;
			$this->assertSameConnection();
			$result = $work( $this );

			if ( $this->transactionFailed ) {
				throw new TransitionFailure(
					TransitionFailure::QUERY_ERROR,
					null,
					null,
					$this->transactionConnectionId
				);
			}

			$control?->reach(
				AtomicLifecycleCheckpoints::BEFORE_COMMIT,
				$this->requiredTransactionConnectionId()
			);
			$this->assertSameConnection();

			if ( ! $this->database->commit() ) {
				throw $this->databaseFailure();
			}

			$this->transactionActive       = false;
			$this->transactionConnectionId = null;

			return $result;
		} catch ( Throwable $failure ) {
			$this->rollbackFailedTransaction();
			$classifiedFailure             = $failure instanceof mysqli_sql_exception
				? $this->databaseFailure( $failure )
				: $failure;
			$this->transactionActive       = false;
			$this->transactionFailed       = true;
			$this->transactionConnectionId = null;

			// phpcs:ignore WordPress.Security.EscapeOutput.ExceptionNotEscaped -- The caught failure is rethrown, not rendered.
			throw $classifiedFailure;
		}
	}

	/**
	 * Executes one parameterized statement inside the owned transaction.
	 *
	 * @param string                      $sql Fixed proof SQL.
	 * @param list<int|float|string|null> $parameters Bound values.
	 * @return int Number of affected rows.
	 * @throws TransitionFailure When the statement cannot complete.
	 */
	public function execute( string $sql, array $parameters = array() ): int {
		$result = $this->executeQuery( $sql, $parameters );

		if ( $result instanceof mysqli_result ) {
			$result->free();
		}

		$affectedRows = $this->database->affected_rows;

		return is_int( $affectedRows ) ? $affectedRows : (int) $affectedRows;
	}

	/**
	 * Reads one parameterized row inside the owned transaction.
	 *
	 * @param string                      $sql Fixed proof SQL.
	 * @param list<int|float|string|null> $parameters Bound values.
	 * @return array<string, mixed>|null
	 * @throws TransitionFailure When the read cannot complete.
	 */
	public function row( string $sql, array $parameters = array() ): ?array {
		$result = $this->executeQuery( $sql, $parameters );

		if ( ! $result instanceof mysqli_result ) {
			// phpcs:ignore WordPress.Security.EscapeOutput.ExceptionNotEscaped -- The fixed exception contains no output-derived material.
			throw new TransitionFailure(
				TransitionFailure::QUERY_ERROR,
				null,
				null,
				$this->transactionConnectionId
			);
		}

		$row = $result->fetch_assoc();
		$result->free();

		return is_array( $row ) ? $row : null;
	}

	/**
	 * Reads parameterized rows inside the owned transaction.
	 *
	 * @param string                      $sql Fixed proof SQL.
	 * @param list<int|float|string|null> $parameters Bound values.
	 * @return list<array<string, mixed>>
	 * @throws TransitionFailure When the read cannot complete.
	 */
	public function rows( string $sql, array $parameters = array() ): array {
		$result = $this->executeQuery( $sql, $parameters );

		if ( ! $result instanceof mysqli_result ) {
			// phpcs:ignore WordPress.Security.EscapeOutput.ExceptionNotEscaped -- The fixed exception contains no output-derived material.
			throw new TransitionFailure(
				TransitionFailure::QUERY_ERROR,
				null,
				null,
				$this->transactionConnectionId
			);
		}

		$rows = array();

		$row = $result->fetch_assoc();

		while ( is_array( $row ) ) {
			$rows[] = $row;
			$row    = $result->fetch_assoc();
		}

		$result->free();

		return $rows;
	}

	/**
	 * Returns the transaction's original physical connection identifier.
	 */
	public function transactionConnectionId(): int {
		return $this->requiredTransactionConnectionId();
	}

	/**
	 * Executes one guarded query.
	 *
	 * @param string                      $sql Fixed proof SQL.
	 * @param list<int|float|string|null> $parameters Bound values.
	 * @return mysqli_result|bool
	 * @throws TransitionFailure When the query cannot complete.
	 */
	private function executeQuery( string $sql, array $parameters ): mysqli_result|bool {
		$this->requireUsableTransaction();
		$this->assertSameConnection();

		try {
			$result = $this->database->execute_query( $sql, $parameters );
		} catch ( mysqli_sql_exception $exception ) {
			$this->transactionFailed = true;

			// phpcs:ignore WordPress.Security.EscapeOutput.ExceptionNotEscaped -- Throws a sanitized classification, never the database message.
			throw $this->databaseFailure( $exception );
		}

		if ( false === $result ) {
			$this->transactionFailed = true;

			throw $this->databaseFailure();
		}

		return $result;
	}

	/**
	 * Rejects statements outside the active transaction or after any failure.
	 *
	 * @throws LogicException When the transaction is not usable.
	 */
	private function requireUsableTransaction(): void {
		if ( ! $this->transactionActive || $this->transactionFailed ) {
			throw new LogicException( 'The disposable proof transaction is not usable.' );
		}
	}

	/**
	 * Proves that the transaction still owns its original physical connection.
	 *
	 * @throws TransitionFailure When the physical connection was lost or changed.
	 */
	private function assertSameConnection(): void {
		$this->requireUsableTransaction();

		try {
			$currentConnectionId = $this->connectionId();
		} catch ( TransitionFailure $failure ) {
			$this->transactionFailed = true;

			// phpcs:ignore WordPress.Security.EscapeOutput.ExceptionNotEscaped -- The fixed exception copies only sanitized numeric fields.
			throw new TransitionFailure(
				TransitionFailure::CONNECTION_LOST,
				$failure->databaseErrorNumber(),
				$failure->sqlStateClass(),
				$this->transactionConnectionId
			);
		}

		if ( $currentConnectionId !== $this->requiredTransactionConnectionId() ) {
			$this->transactionFailed = true;

			// phpcs:ignore WordPress.Security.EscapeOutput.ExceptionNotEscaped -- The fixed exception contains no output-derived material.
			throw new TransitionFailure(
				TransitionFailure::CONNECTION_LOST,
				null,
				null,
				$this->transactionConnectionId
			);
		}
	}

	/**
	 * Returns the captured transaction connection identifier.
	 *
	 * @throws LogicException When no transaction owns the connection.
	 */
	private function requiredTransactionConnectionId(): int {
		if ( null === $this->transactionConnectionId ) {
			throw new LogicException( 'No disposable proof transaction owns the connection.' );
		}

		return $this->transactionConnectionId;
	}

	/**
	 * Attempts full rollback; a lost session has already rolled back server-side.
	 */
	private function rollbackFailedTransaction(): void {
		if ( ! $this->transactionActive ) {
			return;
		}

		try {
			$this->database->rollback();
		} catch ( Throwable $rollbackFailure ) {
			unset( $rollbackFailure );
		}
	}

	/**
	 * Classifies one database failure without preserving or exposing its message.
	 *
	 * @param mysqli_sql_exception|null $databaseException Captured database exception.
	 */
	private function databaseFailure( ?mysqli_sql_exception $databaseException = null ): TransitionFailure {
		$errorNumber = $databaseException instanceof mysqli_sql_exception
			? (int) $databaseException->getCode()
			: ( 0 !== $this->database->errno ? $this->database->errno : null );
		$sqlState    = $databaseException instanceof mysqli_sql_exception
			? $databaseException->getSqlState()
			: $this->database->sqlstate;
		$sqlClass    = 2 <= strlen( $sqlState )
			? substr( $sqlState, 0, 2 )
			: null;
		$kind        = TransitionFailure::QUERY_ERROR;

		if ( 1213 === $errorNumber ) {
			$kind = TransitionFailure::DEADLOCK;
		} elseif ( 1205 === $errorNumber ) {
			$kind = TransitionFailure::LOCK_TIMEOUT;
		} elseif ( in_array( $errorNumber, array( 2006, 2013 ), true ) || '08' === $sqlClass ) {
			$kind = TransitionFailure::CONNECTION_LOST;
		}

		return new TransitionFailure(
			$kind,
			$errorNumber,
			$sqlClass,
			$this->transactionConnectionId
		);
	}
}
