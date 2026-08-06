<?php
/**
 * Slice 0 CIMD metadata-validation tests.
 *
 * @package GalatanOvidiu\Charter
 */

declare(strict_types=1);

namespace GalatanOvidiu\Charter\Tests\Integration\CimdOutboundSafety;

use GalatanOvidiu\Charter\Tests\Prototype\CimdOutboundSafety\ClientIdentifier;
use GalatanOvidiu\Charter\Tests\Prototype\CimdOutboundSafety\MetadataValidator;
use InvalidArgumentException;
use PHPUnit\Framework\TestCase;

/**
 * Proves exact CIMD metadata identity and public-client restrictions.
 *
 * @since 0.1.0
 */
final class MetadataValidationTest extends TestCase {

	/**
	 * Verifies the minimal accepted MCP CIMD projection.
	 *
	 * @since 0.1.0
	 */
	public function testAcceptsExactPublicClientMetadataAndPreservesRedirects(): void {
		$identifier = ClientIdentifier::fromString( 'https://client.example/metadata' );
		$metadata   = MetadataValidator::validate(
			self::document(
				array(
					'redirect_uris' => array(
						'https://client.example/callback',
						'http://127.0.0.1:49152/callback',
						'http://[::1]:49153/callback',
					),
				)
			),
			$identifier
		);

		self::assertSame( $identifier->exact(), $metadata->clientId() );
		self::assertSame( 'Charter proof client', $metadata->clientName() );
		self::assertSame(
			array(
				'https://client.example/callback',
				'http://127.0.0.1:49152/callback',
				'http://[::1]:49153/callback',
			),
			$metadata->redirectUris()
		);
		self::assertSame( 'none', $metadata->tokenEndpointAuthMethod() );
		self::assertTrue( $metadata->hasRedirect( 'https://client.example/callback' ) );
		self::assertFalse( $metadata->hasRedirect( 'https://client.example/Callback' ) );
		self::assertMatchesRegularExpression( '/\A[a-f0-9]{64}\z/', $metadata->fingerprint() );
	}

	/**
	 * Verifies simple-string comparison against the submitted Client Identifier.
	 *
	 * @since 0.1.0
	 *
	 * @dataProvider mismatchedClientIdProvider
	 *
	 * @param string $documentClientId Non-identical document identity.
	 */
	public function testRejectsEveryNonExactDocumentClientId( string $documentClientId ): void {
		$this->expectException( InvalidArgumentException::class );

		MetadataValidator::validate(
			self::document( array( 'client_id' => $documentClientId ) ),
			ClientIdentifier::fromString( 'https://client.example:443/%63imd' )
		);
	}

	/**
	 * Verifies that CIMD cannot acquire a symmetric or asymmetric credential profile.
	 *
	 * @since 0.1.0
	 *
	 * @dataProvider rejectedAuthenticationMetadataProvider
	 *
	 * @param array<string, mixed> $overrides Authentication metadata overrides.
	 */
	public function testRequiresExplicitNoneAndRejectsSecretOrKeyMaterial( array $overrides ): void {
		$this->expectException( InvalidArgumentException::class );

		MetadataValidator::validate(
			self::document( $overrides ),
			ClientIdentifier::fromString( 'https://client.example/metadata' )
		);
	}

	/**
	 * Verifies exact redirect validation under the accepted D07 classes.
	 *
	 * @since 0.1.0
	 *
	 * @dataProvider rejectedRedirectProvider
	 *
	 * @param mixed $redirectUris Invalid redirect set.
	 */
	public function testRejectsInvalidOrDuplicateRedirects( mixed $redirectUris ): void {
		$this->expectException( InvalidArgumentException::class );

		MetadataValidator::validate(
			self::document( array( 'redirect_uris' => $redirectUris ) ),
			ClientIdentifier::fromString( 'https://client.example/metadata' )
		);
	}

	/**
	 * Verifies local callback and exact HTTPS URI boundary forms.
	 *
	 * @since 0.1.0
	 *
	 * @dataProvider acceptedRedirectBoundaryProvider
	 *
	 * @param string $redirectUri Exact accepted redirect URI.
	 */
	public function testAcceptsExactD07RedirectBoundaries( string $redirectUri ): void {
		$metadata = MetadataValidator::validate(
			self::document( array( 'redirect_uris' => array( $redirectUri ) ) ),
			ClientIdentifier::fromString( 'https://client.example/metadata' )
		);

		self::assertSame( array( $redirectUri ), $metadata->redirectUris() );
	}

	/**
	 * Verifies that optional remote URLs remain inert validation data.
	 *
	 * @since 0.1.0
	 */
	public function testAcceptsEmbeddedPublicUrlsWithoutProjectingOrFetchingThem(): void {
		$metadata = MetadataValidator::validate(
			self::document(
				array(
					'client_uri' => 'https://special.invalid/client',
					'logo_uri'   => 'https://special.invalid/logo.png',
					'jwks_uri'   => 'https://special.invalid/jwks.json',
					'policy_uri' => 'https://special.invalid/policy',
					'tos_uri'    => 'https://special.invalid/terms',
				)
			),
			ClientIdentifier::fromString( 'https://client.example/metadata' )
		);

		self::assertSame( 'https://client.example/metadata', $metadata->clientId() );
		self::assertSame( array( 'https://client.example/callback' ), $metadata->redirectUris() );
	}

	/**
	 * Verifies duplicate security members are rejected before JSON projection.
	 *
	 * @since 0.1.0
	 */
	public function testRejectsDuplicateSecurityRelevantRootMembers(): void {
		$this->expectException( InvalidArgumentException::class );

		MetadataValidator::validate(
			'{"client_id":"https://client.example/metadata",'
			. '"client_name":"Charter proof client",'
			. '"redirect_uris":["https://client.example/callback"],'
			. '"redirect_uris":["https://other.example/callback"],'
			. '"token_endpoint_auth_method":"none"}',
			ClientIdentifier::fromString( 'https://client.example/metadata' )
		);
	}

	/**
	 * Verifies every exact approved structural boundary and its first excess.
	 *
	 * @dataProvider structuralBoundaryProvider
	 *
	 * @param array<string, mixed> $overrides Root-member overrides.
	 * @param bool                 $accepted  Whether the boundary value is accepted.
	 */
	public function testEnforcesEveryExactJsonStructuralBound( array $overrides, bool $accepted ): void {
		$identifier = ClientIdentifier::fromString( 'https://client.example/metadata' );

		if ( ! $accepted ) {
			$this->expectException( InvalidArgumentException::class );
		}

		$metadata = MetadataValidator::validate( self::document( $overrides ), $identifier );

		if ( $accepted ) {
			self::assertSame( $identifier->exact(), $metadata->clientId() );
		}
	}

	/**
	 * Verifies the exact 64-member root-object boundary and first excess.
	 *
	 * @dataProvider rootMemberBoundaryProvider
	 *
	 * @param int  $extraMembers Additional inert root members beyond the four required members.
	 * @param bool $accepted     Whether the boundary value is accepted.
	 */
	public function testEnforcesTheExactRootMemberBound( int $extraMembers, bool $accepted ): void {
		$overrides = array();
		for ( $index = 0; $index < $extraMembers; ++$index ) {
			$overrides[ 'inert_' . $index ] = $index;
		}

		$this->testEnforcesEveryExactJsonStructuralBound( $overrides, $accepted );
	}

	/**
	 * Verifies the exact 32-redirect boundary and first excess.
	 *
	 * @dataProvider redirectCountBoundaryProvider
	 *
	 * @param int  $count    Redirect count.
	 * @param bool $accepted Whether the boundary value is accepted.
	 */
	public function testEnforcesTheExactRedirectCountBound( int $count, bool $accepted ): void {
		$redirects = array();
		for ( $index = 0; $index < $count; ++$index ) {
			$redirects[] = 'https://client.example/callback/' . $index;
		}

		$this->testEnforcesEveryExactJsonStructuralBound( array( 'redirect_uris' => $redirects ), $accepted );
	}

	/**
	 * Provides non-identical document client identifiers.
	 *
	 * @since 0.1.0
	 *
	 * @return array<string, array{string}> Mismatched identities.
	 */
	public function mismatchedClientIdProvider(): array {
		return array(
			'default port elided'         => array( 'https://client.example/%63imd' ),
			'host case changed'           => array( 'https://CLIENT.example:443/%63imd' ),
			'path decoded'                => array( 'https://client.example:443/cimd' ),
			'percent escape case changed' => array( 'https://client.example:443/%63IMD' ),
			'trailing slash added'        => array( 'https://client.example:443/%63imd/' ),
		);
	}

	/**
	 * Provides forbidden authentication metadata.
	 *
	 * @since 0.1.0
	 *
	 * @return array<string, array{array<string, mixed>}> Rejected metadata.
	 */
	public function rejectedAuthenticationMetadataProvider(): array {
		return array(
			'method omitted'           => array( array( 'token_endpoint_auth_method' => null ) ),
			'client secret post'       => array( array( 'token_endpoint_auth_method' => 'client_secret_post' ) ),
			'client secret basic'      => array( array( 'token_endpoint_auth_method' => 'client_secret_basic' ) ),
			'private key JWT'          => array( array( 'token_endpoint_auth_method' => 'private_key_jwt' ) ),
			'client secret'            => array( array( 'client_secret' => 'must-not-be-retained' ) ),
			'client secret expiration' => array( array( 'client_secret_expires_at' => 0 ) ),
			'private JWK set'          => array(
				array(
					'jwks' => array(
						'keys' => array(
							array(
								'kty' => 'RSA',
								'd'   => 'private-component-not-retained',
							),
						),
					),
				),
			),
		);
	}

	/**
	 * Provides invalid redirect sets.
	 *
	 * @since 0.1.0
	 *
	 * @return array<string, array{mixed}> Invalid redirects.
	 */
	public function rejectedRedirectProvider(): array {
		return array(
			'empty set'                 => array( array() ),
			'non-array'                 => array( 'https://client.example/callback' ),
			'non-string member'         => array( array( 42 ) ),
			'duplicate member'          => array( array( 'https://client.example/callback', 'https://client.example/callback' ) ),
			'http non-loopback'         => array( array( 'http://client.example/callback' ) ),
			'localhost subdomain'       => array( array( 'http://app.localhost/callback' ) ),
			'localhost suffix'          => array( array( 'http://localhost.example/callback' ) ),
			'IPv4 loopback port zero'   => array( array( 'http://127.0.0.1:0/callback' ) ),
			'IPv6 loopback port zero'   => array( array( 'http://[::1]:0/callback' ) ),
			'custom scheme'             => array( array( 'com.example.app:/callback' ) ),
			'network-path reference'    => array( array( '//client.example/callback' ) ),
			'fragment'                  => array( array( 'https://client.example/callback#fragment' ) ),
			'userinfo'                  => array( array( 'https://user@client.example/callback' ) ),
			'password'                  => array( array( sprintf( 'https://user%cfixture-password%cclient.example/callback', 58, 64 ) ) ),
			'backslash ambiguity'       => array( array( 'https://client.example\\callback' ) ),
			'raw space'                 => array( array( 'https://client.example/call back' ) ),
			'raw control'               => array( array( "https://client.example/call\nback" ) ),
			'incomplete percent escape' => array( array( 'https://client.example/callback%' ) ),
			'short percent escape'      => array( array( 'https://client.example/callback%2' ) ),
			'non-hex percent escape'    => array( array( 'https://client.example/callback%GG' ) ),
			'empty bracket host'        => array( array( 'https://[]/callback' ) ),
			'non-IP bracket host'       => array( array( 'https://[client.example]/callback' ) ),
			'unclosed bracket host'     => array( array( 'https://[::1/callback' ) ),
			'mismatched bracket host'   => array( array( 'https://::1]/callback' ) ),
			'wildcard HTTPS host'       => array( array( 'https://*.example/callback' ) ),
			'invalid DNS label'         => array( array( 'https://-client.example/callback' ) ),
			'invalid IPv4 literal'      => array( array( 'https://999.999.999.999/callback' ) ),
			'raw Unicode host'          => array( array( 'https://clïent.example/callback' ) ),
		);
	}

	/**
	 * Provides exact accepted redirect URI boundary forms.
	 *
	 * @since 0.1.0
	 *
	 * @return array<string, array{string}> Accepted redirect URIs.
	 */
	public function acceptedRedirectBoundaryProvider(): array {
		return array(
			'localhost without port' => array( 'http://localhost/callback' ),
			'localhost runtime port' => array( 'http://localhost:49152/callback' ),
			'IPv4 without port'      => array( 'http://127.0.0.1/callback' ),
			'IPv6 without port'      => array( 'http://[::1]/callback' ),
			'IPv4 first usable port' => array( 'http://127.0.0.1:1/callback' ),
			'IPv4 last usable port'  => array( 'http://127.0.0.1:65535/callback' ),
			'IPv6 first usable port' => array( 'http://[::1]:1/callback' ),
			'IPv6 last usable port'  => array( 'http://[::1]:65535/callback' ),
			'HTTPS query preserved'  => array( 'https://client.example/callback?state=exact%20value' ),
			'HTTPS IPv6 literal'     => array( 'https://[2001:4860:4860::8888]:8443/callback' ),
		);
	}

	/**
	 * Provides exact total-node, member-name, string, client-name, redirect-URI, and depth cases.
	 *
	 * The node definition counts the root object, each array/object container, and each
	 * scalar value. Object member names are bounded separately and are not nodes.
	 *
	 * @return iterable<string, array{array<string, mixed>, bool}> Cases.
	 */
	public function structuralBoundaryProvider(): iterable {
		yield '256 total nodes' => array( array( 'shape' => array_fill( 0, 249, 0 ) ), true );
		yield '257 total nodes' => array( array( 'shape' => array_fill( 0, 250, 0 ) ), false );
		yield '128-byte member name' => array( array( str_repeat( 'k', 128 ) => 0 ), true );
		yield '129-byte member name' => array( array( str_repeat( 'k', 129 ) => 0 ), false );
		yield '2048-byte generic string' => array( array( 'description' => str_repeat( 'g', 2048 ) ), true );
		yield '2049-byte generic string' => array( array( 'description' => str_repeat( 'g', 2049 ) ), false );
		yield '256-byte client name' => array( array( 'client_name' => str_repeat( 'n', 256 ) ), true );
		yield '257-byte client name' => array( array( 'client_name' => str_repeat( 'n', 257 ) ), false );
		yield '2048-byte redirect URI' => array(
			array( 'redirect_uris' => array( self::redirectWithLength( 2048 ) ) ),
			true,
		);
		yield '2049-byte redirect URI' => array(
			array( 'redirect_uris' => array( self::redirectWithLength( 2049 ) ) ),
			false,
		);
		yield 'depth 16' => array( array( 'shape' => self::nestedArray( 15 ) ), true );
		yield 'depth 17' => array( array( 'shape' => self::nestedArray( 16 ) ), false );
	}

	/**
	 * Provides the exact root-member boundary.
	 *
	 * @return iterable<string, array{int, bool}> Cases.
	 */
	public function rootMemberBoundaryProvider(): iterable {
		yield '64 root members' => array( 60, true );
		yield '65 root members' => array( 61, false );
	}

	/**
	 * Provides the exact redirect-count boundary.
	 *
	 * @return iterable<string, array{int, bool}> Cases.
	 */
	public function redirectCountBoundaryProvider(): iterable {
		yield '32 redirects' => array( 32, true );
		yield '33 redirects' => array( 33, false );
	}

	/**
	 * Creates an accepted HTTPS redirect with one exact byte length.
	 *
	 * @param int $length Exact byte length.
	 * @return string Redirect URI.
	 */
	private static function redirectWithLength( int $length ): string {
		$prefix = 'https://client.example/';
		return $prefix . str_repeat( 'r', $length - strlen( $prefix ) );
	}

	/**
	 * Creates an exact nested-array depth below the root object.
	 *
	 * @param int $arrayCount Number of nested arrays.
	 * @return array<mixed> Nested value.
	 */
	private static function nestedArray( int $arrayCount ): array {
		$value = array();
		for ( $depth = 1; $depth < $arrayCount; ++$depth ) {
			$value = array( $value );
		}

		return $value;
	}

	/**
	 * Creates one independently fixed metadata document.
	 *
	 * @since 0.1.0
	 *
	 * @param array<string, mixed> $overrides Root-member overrides. A null value removes a member.
	 * @return string JSON document.
	 */
	private static function document( array $overrides = array() ): string {
		$document = array(
			'client_id'                  => 'https://client.example/metadata',
			'client_name'                => 'Charter proof client',
			'redirect_uris'              => array( 'https://client.example/callback' ),
			'token_endpoint_auth_method' => 'none',
		);

		foreach ( $overrides as $member => $value ) {
			if ( null === $value ) {
				unset( $document[ $member ] );
				continue;
			}

			$document[ $member ] = $value;
		}

		// phpcs:ignore WordPress.WP.AlternativeFunctions.json_encode_json_encode -- Pure bootstrap intentionally excludes WordPress.
		return (string) json_encode( $document, JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES );
	}
}
