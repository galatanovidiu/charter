<?php
/**
 * Owned database transport configuration tests.
 *
 * @package GalatanOvidiu\Charter
 */

declare(strict_types=1);

namespace GalatanOvidiu\Charter\Tests\Unit;

use GalatanOvidiu\Charter\OAuth\TransactionManager;
use PHPUnit\Framework\TestCase;
use ReflectionMethod;
use RuntimeException;

/** Verifies WordPress database client flags are preserved and validated. */
final class TransactionManagerTest extends TestCase {

	/**
	 * Preserves one valid WordPress mysqli flag bitmask.
	 *
	 * @runInSeparateProcess
	 * @preserveGlobalState disabled
	 */
	public function testAcceptsWordPressDatabaseClientFlags(): void {
		define( 'MYSQL_CLIENT_FLAGS', MYSQLI_CLIENT_SSL ); // phpcs:ignore WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedConstantFound -- Exercises the exact WordPress Core configuration constant.

		self::assertSame( MYSQLI_CLIENT_SSL, $this->clientFlags() );
	}

	/**
	 * Rejects a non-integer WordPress mysqli flag configuration.
	 *
	 * @runInSeparateProcess
	 * @preserveGlobalState disabled
	 */
	public function testRejectsInvalidWordPressDatabaseClientFlags(): void {
		define( 'MYSQL_CLIENT_FLAGS', 'unsafe-flags' ); // phpcs:ignore WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedConstantFound -- Exercises the exact WordPress Core configuration constant.

		$this->expectException( RuntimeException::class );
		$this->expectExceptionMessage( 'charter_database_configuration_invalid' );
		$this->clientFlags();
	}

	/**
	 * Returns the private normalized flag value.
	 *
	 * @throws RuntimeException When reflection returns an unexpected value.
	 */
	private function clientFlags(): int {
		$method = new ReflectionMethod( TransactionManager::class, 'clientFlags' );
		$flags  = $method->invoke( null );
		if ( ! is_int( $flags ) ) {
			throw new RuntimeException( 'unexpected_client_flags_type' );
		}

		return $flags;
	}
}
