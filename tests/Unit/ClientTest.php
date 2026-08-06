<?php
/**
 * OAuth client unit tests.
 *
 * @package GalatanOvidiu\Charter
 */

declare(strict_types=1);

namespace GalatanOvidiu\Charter\Tests\Unit;

use GalatanOvidiu\Charter\OAuth\Client;
use PHPUnit\Framework\TestCase;

/**
 * Tests exact redirect matching and the native loopback port exception.
 *
 * @since 0.1.0
 */
final class ClientTest extends TestCase {

	/**
	 * Verifies exact HTTPS redirects and no neighboring destination match.
	 *
	 * @since 0.1.0
	 */
	public function testHttpsRedirectMustMatchExactly(): void {
		$client = new Client( 'https://issuer.example', 'client', 'Client', array( 'https://client.example/callback?fixed=1' ) );

		self::assertTrue( $client->allowsRedirectUri( 'https://client.example/callback?fixed=1' ) );
		self::assertFalse( $client->allowsRedirectUri( 'https://client.example/callback?fixed=2' ) );
		self::assertFalse( $client->allowsRedirectUri( 'https://client.example/other?fixed=1' ) );
	}

	/**
	 * Verifies that a loopback redirect may vary only its runtime port.
	 *
	 * @since 0.1.0
	 */
	public function testLoopbackRedirectMayVaryOnlyItsPort(): void {
		$client = new Client( 'https://issuer.example', 'client', 'Client', array( 'http://127.0.0.1:4000/callback' ) );

		self::assertTrue( $client->allowsRedirectUri( 'http://127.0.0.1:52173/callback' ) );
		self::assertFalse( $client->allowsRedirectUri( 'http://127.0.0.1:52173/other' ) );
		self::assertFalse( $client->allowsRedirectUri( 'http://[::1]:52173/callback' ) );
	}

	/**
	 * Verifies public clients have no secret and may explicitly declare refresh.
	 *
	 * @since 0.1.0
	 */
	public function testPublicClientCapabilitiesAreExplicit(): void {
		$client = new Client(
			'https://issuer.example',
			'public-client',
			'Public client',
			array( 'https://client.example/callback' ),
			Client::AUTH_NONE,
			array( Client::GRANT_AUTHORIZATION_CODE, Client::GRANT_REFRESH_TOKEN )
		);

		self::assertSame( Client::AUTH_NONE, $client->authenticationMethod() );
		self::assertTrue( $client->supportsGrantType( Client::GRANT_AUTHORIZATION_CODE ) );
		self::assertTrue( $client->supportsGrantType( Client::GRANT_REFRESH_TOKEN ) );
		self::assertFalse( $client->authenticatesClientSecret( 'unexpected-secret' ) );
	}

	/**
	 * Verifies confidential client authentication uses only the one-way hash.
	 *
	 * @since 0.1.0
	 */
	public function testConfidentialClientAuthenticatesExactSecret(): void {
		$secret = 'chs_unit-test-secret';
		$client = new Client(
			'https://issuer.example',
			'confidential-client',
			'Confidential client',
			array( 'https://client.example/callback' ),
			Client::AUTH_CLIENT_SECRET_POST,
			array( Client::GRANT_AUTHORIZATION_CODE, Client::GRANT_REFRESH_TOKEN ),
			password_hash( $secret, PASSWORD_DEFAULT )
		);

		self::assertSame( Client::AUTH_CLIENT_SECRET_POST, $client->authenticationMethod() );
		self::assertTrue( $client->authenticatesClientSecret( $secret ) );
		self::assertFalse( $client->authenticatesClientSecret( 'chs_wrong-secret' ) );
		self::assertFalse( $client->authenticatesClientSecret( '' ) );
	}
}
