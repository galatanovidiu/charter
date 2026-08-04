<?php
/**
 * Exact disposable-user ownership for the Slice 0 P2 runners.
 *
 * @package GalatanOvidiu\Charter
 */

declare(strict_types=1);

namespace GalatanOvidiu\Charter\Tests\Fixtures\RestAuthenticationBoundary;

use RuntimeException;
use WP_Error;

/**
 * Creates and removes only the two users owned by one exact proof run.
 */
final class OwnedProofUsers {

	private const LOGIN_PREFIX_A = 'charter_p2_a_';

	private const LOGIN_PREFIX_B = 'charter_p2_b_';

	/**
	 * User IDs created by this object.
	 *
	 * @var list<int>
	 */
	private array $createdUserIds = array();

	/**
	 * Validated run identifier.
	 *
	 * @var string
	 */
	private string $runId;

	/**
	 * Establishes exact ownership for one run.
	 *
	 * @param string $run_id Lower-case 16-character hexadecimal run identifier.
	 * @throws RuntimeException When the identifier is outside the fixed contract.
	 */
	public function __construct( string $run_id ) {
		if ( 1 !== preg_match( '/\A[a-f0-9]{16}\z/D', $run_id ) ) {
			throw new RuntimeException( 'Invalid disposable proof run identifier.' );
		}

		$this->runId = $run_id;
	}

	/**
	 * Creates both proof-owned users and returns their numeric IDs.
	 *
	 * @return array{user_a_id: int, user_b_id: int}
	 * @throws RuntimeException When exact ownership cannot be established.
	 */
	public function create(): array {
		$login_a = self::loginFor( $this->runId, 'a' );
		$login_b = self::loginFor( $this->runId, 'b' );

		if ( false !== username_exists( $login_a ) || false !== username_exists( $login_b ) ) {
			throw new RuntimeException( 'Disposable proof user already exists.' );
		}

		try {
			$user_a_id = $this->createUser( $login_a, 'administrator' );
			$user_b_id = $this->createUser( $login_b, 'subscriber' );
		} catch ( RuntimeException $exception ) {
			$this->cleanup();

			throw $exception;
		}

		return array(
			'user_a_id' => $user_a_id,
			'user_b_id' => $user_b_id,
		);
	}

	/**
	 * Removes the exact users this object created.
	 */
	public function cleanup(): bool {
		$result = true;

		foreach ( array_reverse( $this->createdUserIds ) as $user_id ) {
			$result = self::deleteUser( $user_id ) && $result;
		}

		$this->createdUserIds = array();

		return $result;
	}

	/**
	 * Removes exact users left by an interrupted run.
	 *
	 * @param string $run_id Lower-case 16-character hexadecimal run identifier.
	 */
	public static function cleanupRun( string $run_id ): bool {
		if ( 1 !== preg_match( '/\A[a-f0-9]{16}\z/D', $run_id ) ) {
			return false;
		}

		$result = true;

		foreach ( array( self::loginFor( $run_id, 'a' ), self::loginFor( $run_id, 'b' ) ) as $login ) {
			$user = get_user_by( 'login', $login );

			if ( false !== $user ) {
				$result = self::deleteUser( (int) $user->ID ) && $result;
			}
		}

		return $result
			&& false === username_exists( self::loginFor( $run_id, 'a' ) )
			&& false === username_exists( self::loginFor( $run_id, 'b' ) );
	}

	/**
	 * Creates one user with random proof-only authentication material.
	 *
	 * @param string $login Exact proof-owned login.
	 * @param string $role  Exact proof-owned site role.
	 * @throws RuntimeException When WordPress rejects the user.
	 */
	private function createUser( string $login, string $role ): int {
		$user_id = wp_insert_user(
			array(
				'user_login' => $login,
				'user_pass'  => bin2hex( random_bytes( 32 ) ),
				'user_email' => $login . '@example.invalid',
				'role'       => $role,
			)
		);

		if ( $user_id instanceof WP_Error || 1 > $user_id ) {
			throw new RuntimeException( 'Could not create disposable proof user.' );
		}

		$this->createdUserIds[] = $user_id;

		return $user_id;
	}

	/**
	 * Deletes one exact user without reassigning content.
	 *
	 * @param int $user_id Exact proof-owned user ID.
	 */
	private static function deleteUser( int $user_id ): bool {
		if ( is_multisite() && function_exists( 'wpmu_delete_user' ) ) {
			return wpmu_delete_user( $user_id );
		}

		if ( ! function_exists( 'wp_delete_user' ) ) {
			require_once ABSPATH . 'wp-admin/includes/user.php';
		}

		return wp_delete_user( $user_id );
	}

	/**
	 * Returns one exact proof-owned login.
	 *
	 * @param string $run_id Validated run identifier.
	 * @param string $user   Fixed user label.
	 */
	private static function loginFor( string $run_id, string $user ): string {
		return 'a' === $user ? self::LOGIN_PREFIX_A . $run_id : self::LOGIN_PREFIX_B . $run_id;
	}
}
