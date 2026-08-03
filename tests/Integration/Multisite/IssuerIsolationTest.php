<?php
/**
 * Slice 0 issuer identity and sibling-isolation integration tests.
 *
 * @package GalatanOvidiu\Charter
 */

declare(strict_types=1);

namespace GalatanOvidiu\Charter\Tests\Integration\Multisite;

use GalatanOvidiu\Charter\Tests\Prototype\Multisite\IssuerIdentity;
use GalatanOvidiu\Charter\Tests\Prototype\Multisite\NetworkAdminSelection;
use GalatanOvidiu\Charter\Tests\Prototype\Multisite\ProofCredentialStore;
use GalatanOvidiu\Charter\Tests\Prototype\Multisite\SiteIssuerLifecycle;
use WP_UnitTestCase;

/**
 * Proves that WordPress topology never substitutes for issuer identity.
 *
 * @since 0.1.0
 */
final class IssuerIsolationTest extends WP_UnitTestCase {

	/**
	 * Clears disposable issuer records before each proof case.
	 *
	 * @since 0.1.0
	 */
	public function setUp(): void {
		parent::setUp();

		SiteIssuerLifecycle::resetProof();
		ProofCredentialStore::resetProof();
	}

	/**
	 * Verifies independent state for the main and subdomain-shaped origins.
	 *
	 * @since 0.1.0
	 */
	public function testMainSiteOriginIsIndependentFromSubdomainShapedSiteOrigin(): void {
		$mainSiteId      = get_main_site_id();
		$subdomainId     = self::createOriginAddressedSite( 'team.example.org' );
		$mainIdentity    = IssuerIdentity::forSite( $mainSiteId );
		$subdomainIssuer = IssuerIdentity::forSite( $subdomainId )->issuer();

		NetworkAdminSelection::prepareSite( $mainSiteId );
		NetworkAdminSelection::prepareSite( $subdomainId );

		self::assertNotSame( $mainIdentity->issuer(), $subdomainIssuer );
		self::assertTrue( SiteIssuerLifecycle::recordVerification( $mainIdentity->issuer() ) );
		self::assertTrue( SiteIssuerLifecycle::enable( $mainIdentity->issuer() ) );
		self::assertSame( SiteIssuerLifecycle::ENABLED, SiteIssuerLifecycle::stateFor( $mainIdentity->issuer() ) );
		self::assertSame( SiteIssuerLifecycle::PREPARED, SiteIssuerLifecycle::stateFor( $subdomainIssuer ) );
	}

	/**
	 * Verifies that a mapped public origin is not aliased to its internal address.
	 *
	 * @since 0.1.0
	 */
	public function testDomainMappedOriginIsIndependentFromInternalWordPressAddress(): void {
		$siteId         = self::createOriginAddressedSite( 'internal.example.test' );
		$internalIssuer = IssuerIdentity::forSite( $siteId )->issuer();

		update_blog_option( $siteId, 'home', 'https://mapped.example.org' );
		$mappedIssuer = IssuerIdentity::forSite( $siteId )->issuer();

		NetworkAdminSelection::prepareSite( $siteId );

		self::assertSame( 'https://mapped.example.org', $mappedIssuer );
		self::assertNotSame( $internalIssuer, $mappedIssuer );
		self::assertSame( SiteIssuerLifecycle::PREPARED, SiteIssuerLifecycle::stateFor( $mappedIssuer ) );
		self::assertSame( SiteIssuerLifecycle::AVAILABLE, SiteIssuerLifecycle::stateFor( $internalIssuer ) );
		self::assertFalse( SiteIssuerLifecycle::hasIssuer( $internalIssuer ) );
	}

	/**
	 * Verifies that a stored path-bearing identity cannot operate in v1.
	 *
	 * @since 0.1.0
	 */
	public function testPathBearingCanonicalIssuerCanBeStoredButCannotOperateInV1(): void {
		$identity = IssuerIdentity::forCanonicalIssuer(
			self::createOriginAddressedSite( 'path-identity.example.org' ),
			'https://public.example.org/team'
		);

		SiteIssuerLifecycle::prepare( $identity );

		self::assertTrue( SiteIssuerLifecycle::hasIssuer( 'https://public.example.org/team' ) );
		self::assertSame(
			SiteIssuerLifecycle::PREPARED,
			SiteIssuerLifecycle::stateFor( 'https://public.example.org/team' )
		);
		self::assertTrue( SiteIssuerLifecycle::recordVerification( 'https://public.example.org/team' ) );
		self::assertTrue( SiteIssuerLifecycle::enable( 'https://public.example.org/team' ) );
		self::assertFalse( SiteIssuerLifecycle::isEnabledForV1Operation( $identity ) );
	}

	/**
	 * Verifies that a site locator cannot alias two explicit issuer records.
	 *
	 * @since 0.1.0
	 */
	public function testTwoIssuersCanShareSiteLocatorWithoutAliasing(): void {
		$siteId         = self::createOriginAddressedSite( 'shared-locator.example.org' );
		$firstIdentity  = IssuerIdentity::forCanonicalIssuer( $siteId, 'https://first.example.org' );
		$secondIdentity = IssuerIdentity::forCanonicalIssuer( $siteId, 'https://second.example.org' );
		$firstIssuer    = $firstIdentity->issuer();
		$secondIssuer   = $secondIdentity->issuer();

		SiteIssuerLifecycle::prepare( $firstIdentity );
		SiteIssuerLifecycle::prepare( $secondIdentity );

		self::assertTrue( SiteIssuerLifecycle::recordVerification( $firstIssuer ) );
		self::assertTrue( SiteIssuerLifecycle::enable( $firstIssuer ) );
		self::assertSame( SiteIssuerLifecycle::ENABLED, SiteIssuerLifecycle::stateFor( $firstIssuer ) );
		self::assertSame( SiteIssuerLifecycle::PREPARED, SiteIssuerLifecycle::stateFor( $secondIssuer ) );
		self::assertTrue( SiteIssuerLifecycle::hasIssuer( $firstIssuer ) );
		self::assertTrue( SiteIssuerLifecycle::hasIssuer( $secondIssuer ) );
	}

	/**
	 * Verifies that wrong WordPress context cannot redirect an issuer lookup.
	 *
	 * @since 0.1.0
	 */
	public function testWrongSiteContextCannotSubstituteForExplicitIssuerLookup(): void {
		$issuerSiteId  = self::createOriginAddressedSite( 'issuer-context.example.org' );
		$siblingSiteId = self::createOriginAddressedSite( 'wrong-context.example.org' );
		$issuer        = IssuerIdentity::forSite( $issuerSiteId )->issuer();

		NetworkAdminSelection::prepareSite( $issuerSiteId );
		switch_to_blog( $siblingSiteId );

		try {
			$currentContextIssuer = IssuerIdentity::forCurrentSite()->issuer();

			self::assertNotSame( $issuer, $currentContextIssuer );
			self::assertSame( SiteIssuerLifecycle::AVAILABLE, SiteIssuerLifecycle::stateFor( $currentContextIssuer ) );
			self::assertFalse( SiteIssuerLifecycle::hasIssuer( $currentContextIssuer ) );
			self::assertSame( SiteIssuerLifecycle::PREPARED, SiteIssuerLifecycle::stateFor( $issuer ) );
		} finally {
			restore_current_blog();
		}
	}

	/**
	 * Verifies exact issuer and resource binding under deliberately wrong context.
	 *
	 * @since 0.1.0
	 */
	public function testProofCredentialIsRejectedBySiblingUnderWrongSiteContext(): void {
		$issuerSiteId    = self::createOriginAddressedSite( 'credential-a.example.org' );
		$siblingSiteId   = self::createOriginAddressedSite( 'credential-b.example.org' );
		$issuerIdentity  = IssuerIdentity::forSite( $issuerSiteId );
		$siblingIdentity = IssuerIdentity::forSite( $siblingSiteId );

		self::enableIdentity( $issuerIdentity );
		self::enableIdentity( $siblingIdentity );
		ProofCredentialStore::issue( 'credential-for-a', $issuerIdentity, $issuerIdentity->issuer() );

		switch_to_blog( $siblingSiteId );

		try {
			self::assertTrue(
				ProofCredentialStore::accepts( 'credential-for-a', $issuerIdentity, $issuerIdentity->issuer() )
			);
			self::assertFalse(
				ProofCredentialStore::accepts( 'credential-for-a', $siblingIdentity, $siblingIdentity->issuer() )
			);
			self::assertFalse(
				ProofCredentialStore::accepts( 'credential-for-a', $issuerIdentity, $siblingIdentity->issuer() )
			);
		} finally {
			restore_current_blog();
		}
	}

	/**
	 * Verifies that request host input cannot replace the established issuer.
	 *
	 * @since 0.1.0
	 */
	public function testHostAndForwardedInputCannotRedefineStoredIssuer(): void {
		$siteId   = self::createOriginAddressedSite( 'stored-issuer.example.org' );
		$identity = IssuerIdentity::forSite( $siteId );
		$issuer   = $identity->issuer();
		$server   = $_SERVER;

		self::enableIdentity( $identity );
		ProofCredentialStore::issue( 'host-proof-credential', $identity, $issuer );

		$_SERVER['HTTP_HOST']              = 'attacker.example.net';
		$_SERVER['SERVER_NAME']            = 'attacker.example.net';
		$_SERVER['HTTP_X_FORWARDED_HOST']  = 'forwarded-attacker.example.net';
		$_SERVER['HTTP_X_FORWARDED_PROTO'] = 'https';
		switch_to_blog( $siteId );

		try {
			$requestIdentity = IssuerIdentity::forCurrentSite();

			self::assertSame( $issuer, $requestIdentity->issuer() );
			self::assertSame( SiteIssuerLifecycle::ENABLED, SiteIssuerLifecycle::stateFor( $requestIdentity->issuer() ) );
			self::assertTrue( ProofCredentialStore::accepts( 'host-proof-credential', $requestIdentity, $issuer ) );
		} finally {
			restore_current_blog();
			$_SERVER = $server;
		}
	}

	/**
	 * Verifies that identity construction remains inside its named boundary.
	 *
	 * @since 0.1.0
	 */
	public function testOnlyIssuerIdentityBoundaryUsesWordPressIdentitySources(): void {
		$identityBoundary = realpath( CHARTER_TEST_ROOT . '/tests/Prototype/Multisite/IssuerIdentity.php' );
		$violations       = array();
		$forbiddenCalls   = array( 'get_current_blog_id', 'home_url', 'site_url' );

		self::assertIsString( $identityBoundary );

		foreach ( self::identityBoundaryScanFiles() as $file ) {
			if ( $identityBoundary === $file ) {
				continue;
			}

			// phpcs:ignore WordPress.WP.AlternativeFunctions.file_get_contents_file_get_contents -- Reads local source for a static boundary assertion.
			$contents = file_get_contents( $file );

			self::assertIsString( $contents );

			foreach ( $forbiddenCalls as $forbiddenCall ) {
				$pattern = '/(?<![A-Za-z0-9_])' . preg_quote( $forbiddenCall, '/' ) . '\\s*\\(/';

				if ( 1 === preg_match( $pattern, $contents ) ) {
					$violations[] = str_replace( CHARTER_TEST_ROOT . '/', '', $file ) . ': ' . $forbiddenCall;
				}
			}
		}

		self::assertSame(
			array(),
			$violations,
			"Only tests/Prototype/Multisite/IssuerIdentity.php may read WordPress identity sources.\n" . implode( "\n", $violations )
		);
	}

	/**
	 * Moves one explicit issuer identity to Enabled.
	 *
	 * @since 0.1.0
	 *
	 * @param IssuerIdentity $identity The issuer identity to enable.
	 */
	private static function enableIdentity( IssuerIdentity $identity ): void {
		SiteIssuerLifecycle::prepare( $identity );
		self::assertTrue( SiteIssuerLifecycle::recordVerification( $identity->issuer() ) );
		self::assertTrue( SiteIssuerLifecycle::enable( $identity->issuer() ) );
	}

	/**
	 * Lists production and proof PHP files covered by the identity boundary.
	 *
	 * @since 0.1.0
	 *
	 * @return list<string> Absolute PHP file paths.
	 */
	private static function identityBoundaryScanFiles(): array {
		$files = array( CHARTER_TEST_ROOT . '/charter.php' );

		foreach ( array( '/src', '/tests/Prototype/Multisite' ) as $directory ) {
			$iterator = new \RecursiveIteratorIterator(
				new \RecursiveDirectoryIterator(
					CHARTER_TEST_ROOT . $directory,
					\FilesystemIterator::SKIP_DOTS
				)
			);

			foreach ( $iterator as $file ) {
				if ( $file->isFile() && 'php' === $file->getExtension() ) {
					$files[] = $file->getPathname();
				}
			}
		}

		sort( $files );

		return $files;
	}

	/**
	 * Creates a supported origin-addressed Multisite site.
	 *
	 * @since 0.1.0
	 *
	 * @param string $domain The site's public domain.
	 * @return int The WordPress site locator.
	 */
	private static function createOriginAddressedSite( string $domain ): int {
		return self::factory()->blog->create(
			array(
				'domain' => $domain,
				'path'   => '/',
			)
		);
	}
}
