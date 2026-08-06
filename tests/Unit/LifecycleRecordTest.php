<?php
/**
 * OAuth lifecycle record unit tests.
 *
 * @package GalatanOvidiu\Charter
 */

declare(strict_types=1);

namespace GalatanOvidiu\Charter\Tests\Unit;

use GalatanOvidiu\Charter\OAuth\CredentialRecord;
use GalatanOvidiu\Charter\OAuth\GrantRecord;
use PHPUnit\Framework\TestCase;

/**
 * Tests authoritative half-open expiry and lifecycle state boundaries.
 *
 * @since 0.1.0
 */
final class LifecycleRecordTest extends TestCase {

	/**
	 * Verifies credentials become invalid at their exact expiration second.
	 *
	 * @since 0.1.0
	 */
	public function testCredentialUsesHalfOpenLifetime(): void {
		$record = new CredentialRecord(
			1,
			'access_token',
			'https://issuer.example',
			'https://issuer.example',
			'client',
			'https://client.example/callback',
			2,
			'wordpress:access', // phpcs:ignore WordPress.WP.CapitalPDangit.MisspelledInText -- OAuth scope identifiers are case-sensitive protocol values.
			'',
			null,
			100,
			null,
			3
		);

		self::assertTrue( $record->isActiveAt( 99 ) );
		self::assertFalse( $record->isActiveAt( 100 ) );
		self::assertFalse( $record->isActiveAt( 101 ) );
	}

	/**
	 * Verifies continuing grants close at either exact refresh boundary.
	 *
	 * @since 0.1.0
	 */
	public function testContinuingGrantUsesBothHalfOpenRefreshLifetimes(): void {
		$grant = new GrantRecord(
			3,
			'https://issuer.example',
			'https://issuer.example',
			'client',
			'https://client.example/callback',
			2,
			'wordpress:access', // phpcs:ignore WordPress.WP.CapitalPDangit.MisspelledInText -- OAuth scope identifiers are case-sensitive protocol values.
			true,
			'active',
			1,
			50,
			100,
			80
		);

		self::assertTrue( $grant->isActiveAt( 79, true ) );
		self::assertFalse( $grant->isActiveAt( 80, true ) );
		self::assertTrue( $grant->isActiveAt( 100 ), 'An expired refresh window does not retroactively expire access tokens.' );
	}

	/**
	 * Verifies a terminal grant never becomes active again.
	 *
	 * @since 0.1.0
	 */
	public function testTerminalGrantIsNeverActive(): void {
		$grant = new GrantRecord(
			3,
			'https://issuer.example',
			'https://issuer.example',
			'client',
			'https://client.example/callback',
			2,
			'wordpress:access', // phpcs:ignore WordPress.WP.CapitalPDangit.MisspelledInText -- OAuth scope identifiers are case-sensitive protocol values.
			false,
			'revoked',
			1,
			50,
			null,
			null
		);

		self::assertFalse( $grant->isActiveAt( 2 ) );
	}

	/**
	 * Verifies retained history exposes only its stable terminal metadata.
	 *
	 * @since 0.1.0
	 */
	public function testRevokedGrantCarriesRetainedReasonAndTimestamp(): void {
		$grant = new GrantRecord(
			4,
			'https://issuer.example',
			'https://issuer.example',
			'client',
			'https://client.example/callback',
			2,
			'wordpress:access', // phpcs:ignore WordPress.WP.CapitalPDangit.MisspelledInText -- OAuth scope identifiers are case-sensitive protocol values.
			false,
			'revoked',
			1,
			50,
			null,
			null,
			'',
			75,
			'administrator_grant_revocation'
		);

		self::assertSame( 75, $grant->revokedAt() );
		self::assertSame( 'administrator_grant_revocation', $grant->revocationReason() );
	}
}
