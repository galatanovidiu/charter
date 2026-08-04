<?php
/**
 * Slice 0 credential and root-key behavior integration tests.
 *
 * @package GalatanOvidiu\Charter
 */

declare(strict_types=1);

namespace GalatanOvidiu\Charter\Tests\Integration\Multisite;

use Closure;
use GalatanOvidiu\Charter\Tests\Prototype\Multisite\DigestedProofCredentialStore;
use GalatanOvidiu\Charter\Tests\Prototype\Multisite\EffectiveRootKeySource;
use GalatanOvidiu\Charter\Tests\Prototype\Multisite\ExplicitKeyGuard;
use GalatanOvidiu\Charter\Tests\Prototype\Multisite\IssuerIdentity;
use GalatanOvidiu\Charter\Tests\Prototype\Multisite\RootKeyProofState;
use GalatanOvidiu\Charter\Tests\Prototype\Multisite\SiteIssuerLifecycle;
use WP_UnitTestCase;

/**
 * Proves disposable credential behavior through the approved public seams.
 *
 * @since 0.1.0
 */
final class CredentialRootKeyBehaviorTest extends WP_UnitTestCase {

	/**
	 * Current deterministic WordPress proof phase.
	 *
	 * @since 0.1.0
	 *
	 * @var string
	 */
	private string $wordpressPhase = 'phase-a';

	/**
	 * Optional single scheme changed by the deterministic filter.
	 *
	 * @since 0.1.0
	 *
	 * @var string|null
	 */
	private ?string $changedWordPressScheme = null;

	/**
	 * Scheme names observed by the public WordPress filter.
	 *
	 * @since 0.1.0
	 *
	 * @var list<string>
	 */
	private array $observedWordPressSchemes = array();

	/**
	 * Installed deterministic salt filter, when used by a test.
	 *
	 * @since 0.1.0
	 *
	 * @var Closure|null
	 */
	private ?Closure $saltFilter = null;

	/**
	 * Clears every disposable root-key proof store before each case.
	 *
	 * @since 0.1.0
	 */
	public function setUp(): void {
		parent::setUp();

		SiteIssuerLifecycle::resetProof();
		DigestedProofCredentialStore::resetProof();
		ExplicitKeyGuard::resetProof();
		RootKeyProofState::resetProof();
	}

	/**
	 * Removes the deterministic salt filter before WordPress test cleanup.
	 *
	 * @since 0.1.0
	 */
	public function tearDown(): void {
		if ( $this->saltFilter instanceof Closure ) {
			remove_filter( 'salt', $this->saltFilter, PHP_INT_MAX );
		}

		parent::tearDown();
	}

	/**
	 * Verifies the exact D27 wp_salt() call set and fixed order.
	 *
	 * @since 0.1.0
	 */
	public function testWordPressDerivedRootConsumesExactlyFourEffectiveSchemesInFixedOrder(): void {
		$this->installDeterministicSaltFilter();
		$this->observedWordPressSchemes = array();

		$source = EffectiveRootKeySource::fromWordPress();

		self::assertSame( EffectiveRootKeySource::MODE_WORDPRESS, $source->mode() );
		self::assertFalse( $source->usesExplicitSnapshot() );
		self::assertSame(
			array( 'auth', 'secure_auth', 'logged_in', 'nonce' ),
			$source->observedWordPressSchemes(),
			'The source did not report the fixed public WordPress scheme order.'
		);
		self::assertSame(
			array( 'auth', 'secure_auth', 'logged_in', 'nonce' ),
			$this->observedWordPressSchemes,
			'The public WordPress filter did not observe the fixed scheme order.'
		);
	}

	/**
	 * Verifies digest-only persistence and exact issuer/type separation.
	 *
	 * @since 0.1.0
	 */
	public function testPersistedProofIsDigestOnlyAndSeparatesIssuerAndCredentialTypeDomains(): void {
		$this->installDeterministicSaltFilter();
		$firstIdentity  = self::enabledIdentity( 'digest-first.example.org' );
		$secondIdentity = self::enabledIdentity( 'digest-second.example.org' );
		$source         = EffectiveRootKeySource::fromWordPress();
		$sharedProof    = self::proofPlaceholder( 'credential', 'shared-domain-proof' );
		$exclusiveProof = self::proofPlaceholder( 'credential', 'exclusive-domain-proof' );

		self::assertTrue(
			DigestedProofCredentialStore::issue(
				$sharedProof,
				$source,
				$firstIdentity,
				$firstIdentity->issuer(),
				'access'
			)
		);
		self::assertTrue(
			DigestedProofCredentialStore::issue(
				$sharedProof,
				$source,
				$secondIdentity,
				$secondIdentity->issuer(),
				'access'
			)
		);
		self::assertTrue(
			DigestedProofCredentialStore::issue(
				$sharedProof,
				$source,
				$firstIdentity,
				$firstIdentity->issuer(),
				'refresh'
			)
		);

		self::assertSame(
			3,
			DigestedProofCredentialStore::recordCount(),
			'The same opaque proof did not persist in three separate credential domains.'
		);
		self::assertTrue(
			DigestedProofCredentialStore::issue(
				$exclusiveProof,
				$source,
				$firstIdentity,
				$firstIdentity->issuer(),
				'access'
			)
		);
		self::assertTrue(
			DigestedProofCredentialStore::accepts(
				$exclusiveProof,
				$source,
				$firstIdentity,
				$firstIdentity->issuer(),
				'access'
			)
		);
		self::assertFalse(
			DigestedProofCredentialStore::accepts(
				$exclusiveProof,
				$source,
				$secondIdentity,
				$secondIdentity->issuer(),
				'access'
			),
			'A proof credential crossed an exact issuer boundary.'
		);
		self::assertFalse(
			DigestedProofCredentialStore::accepts(
				$exclusiveProof,
				$source,
				$firstIdentity,
				$firstIdentity->issuer(),
				'refresh'
			),
			'A proof credential crossed a named credential-type boundary.'
		);

		$evidence = DigestedProofCredentialStore::sanitizedEvidence();

		self::assertTrue( $evidence['digest_only'], 'Persisted proof state included an unsupported field shape.' );
		self::assertSame( 4, $evidence['record_count'] );
		self::assertCount( 4, $evidence['records'] );

		foreach ( $evidence['records'] as $record ) {
			self::assertSame(
				array( 'site_id', 'issuer', 'resource', 'credential_type' ),
				array_keys( $record ),
				'The sanitized persistence projection exposed secret-bearing fields.'
			);
		}

		self::assertFalse(
			DigestedProofCredentialStore::persistedStateContains( $sharedProof ),
			'Raw proof credential material appeared in persistence.'
		);
		self::assertFalse(
			DigestedProofCredentialStore::persistedStateContains( $exclusiveProof ),
			'Raw proof credential material appeared in persistence.'
		);

		foreach ( EffectiveRootKeySource::WORDPRESS_SCHEMES as $scheme ) {
			self::assertFalse(
				DigestedProofCredentialStore::persistedStateContains(
					self::wordpressSaltPlaceholder( 'phase-a', $scheme )
				),
				'Effective WordPress root material appeared in persistence.'
			);
		}
	}

	/**
	 * Verifies that current blog context cannot redirect an explicit domain.
	 *
	 * @since 0.1.0
	 */
	public function testWrongBlogContextCannotSelectSiblingCredentialDomainBeforeOrAfterRootChange(): void {
		$this->installDeterministicSaltFilter();
		$firstIdentity  = self::enabledIdentity( 'context-first.example.org' );
		$secondIdentity = self::enabledIdentity( 'context-second.example.org' );
		$phaseASource   = EffectiveRootKeySource::fromWordPress();
		$phaseAProof    = self::proofPlaceholder( 'credential', 'wrong-context-phase-a' );

		self::assertTrue(
			DigestedProofCredentialStore::issue(
				$phaseAProof,
				$phaseASource,
				$firstIdentity,
				$firstIdentity->issuer(),
				'access'
			)
		);

		switch_to_blog( $secondIdentity->siteId() );

		try {
			self::assertTrue(
				DigestedProofCredentialStore::accepts(
					$phaseAProof,
					$phaseASource,
					$firstIdentity,
					$firstIdentity->issuer(),
					'access'
				)
			);
			self::assertFalse(
				DigestedProofCredentialStore::accepts(
					$phaseAProof,
					$phaseASource,
					$secondIdentity,
					$secondIdentity->issuer(),
					'access'
				),
				'Wrong blog context selected a sibling credential domain.'
			);

			$this->wordpressPhase = 'phase-b';
			$phaseBSource         = EffectiveRootKeySource::fromWordPress();
			$phaseBProof          = self::proofPlaceholder( 'credential', 'wrong-context-phase-b' );

			self::assertFalse(
				DigestedProofCredentialStore::accepts(
					$phaseAProof,
					$phaseBSource,
					$firstIdentity,
					$firstIdentity->issuer(),
					'access'
				),
				'A prior-root credential remained accepted under wrong blog context.'
			);
			self::assertTrue(
				DigestedProofCredentialStore::issue(
					$phaseBProof,
					$phaseBSource,
					$firstIdentity,
					$firstIdentity->issuer(),
					'access'
				)
			);
			self::assertFalse(
				DigestedProofCredentialStore::accepts(
					$phaseBProof,
					$phaseBSource,
					$secondIdentity,
					$secondIdentity->issuer(),
					'access'
				),
				'Wrong blog context selected a sibling credential domain after root change.'
			);
		} finally {
			restore_current_blog();
		}
	}

	/**
	 * Verifies uninterrupted sibling operation across WordPress-derived change.
	 *
	 * @since 0.1.0
	 */
	public function testWordPressDerivedChangeRejectsOldSiblingCredentialsButPreservesLifecycleAndSentinels(): void {
		$this->installDeterministicSaltFilter();
		$availableIdentity = IssuerIdentity::forSite( self::createOriginAddressedSite( 'root-available.example.org' ) );
		$preparedIdentity  = IssuerIdentity::forSite( self::createOriginAddressedSite( 'root-prepared.example.org' ) );
		$firstIdentity     = self::enabledIdentity( 'root-enabled-first.example.org' );
		$secondIdentity    = self::enabledIdentity( 'root-enabled-second.example.org' );

		SiteIssuerLifecycle::prepare( $preparedIdentity );
		RootKeyProofState::seedSentinels( $firstIdentity->issuer() );
		RootKeyProofState::seedSentinels( $secondIdentity->issuer() );

		$sentinelState  = RootKeyProofState::stateFingerprint();
		$phaseASource   = EffectiveRootKeySource::fromWordPress();
		$firstOldProof  = self::proofPlaceholder( 'credential', 'first-phase-a' );
		$secondOldProof = self::proofPlaceholder( 'credential', 'second-phase-a' );

		self::assertTrue( self::issueAccessProof( $firstOldProof, $phaseASource, $firstIdentity ) );
		self::assertTrue( self::issueAccessProof( $secondOldProof, $phaseASource, $secondIdentity ) );

		$credentialState      = DigestedProofCredentialStore::stateFingerprint();
		$this->wordpressPhase = 'phase-b';
		$phaseBSource         = EffectiveRootKeySource::fromWordPress();

		self::assertFalse( $phaseASource->sameRootAs( $phaseBSource ) );
		self::assertFalse( self::acceptsAccessProof( $firstOldProof, $phaseBSource, $firstIdentity ) );
		self::assertFalse( self::acceptsAccessProof( $secondOldProof, $phaseBSource, $secondIdentity ) );
		self::assertTrue(
			hash_equals( $credentialState, DigestedProofCredentialStore::stateFingerprint() ),
			'Prior-root rejection mutated persisted credential proof state.'
		);

		self::assertSame( SiteIssuerLifecycle::AVAILABLE, SiteIssuerLifecycle::stateFor( $availableIdentity->issuer() ) );
		self::assertSame( SiteIssuerLifecycle::PREPARED, SiteIssuerLifecycle::stateFor( $preparedIdentity->issuer() ) );
		self::assertSame( SiteIssuerLifecycle::ENABLED, SiteIssuerLifecycle::stateFor( $firstIdentity->issuer() ) );
		self::assertSame( SiteIssuerLifecycle::ENABLED, SiteIssuerLifecycle::stateFor( $secondIdentity->issuer() ) );
		self::assertTrue( RootKeyProofState::sentinelsIntactFor( $firstIdentity->issuer() ) );
		self::assertTrue( RootKeyProofState::sentinelsIntactFor( $secondIdentity->issuer() ) );
		self::assertTrue(
			hash_equals( $sentinelState, RootKeyProofState::stateFingerprint() ),
			'WordPress-derived change mutated non-credential proof state.'
		);
		self::assertSame( 0, ExplicitKeyGuard::adoptionCount(), 'WordPress-derived change invoked adoption.' );

		$firstNewProof  = self::proofPlaceholder( 'credential', 'first-phase-b' );
		$secondNewProof = self::proofPlaceholder( 'credential', 'second-phase-b' );

		self::assertTrue( self::issueAccessProof( $firstNewProof, $phaseBSource, $firstIdentity ) );
		self::assertTrue( self::issueAccessProof( $secondNewProof, $phaseBSource, $secondIdentity ) );
		self::assertTrue( self::acceptsAccessProof( $firstNewProof, $phaseBSource, $firstIdentity ) );
		self::assertTrue( self::acceptsAccessProof( $secondNewProof, $phaseBSource, $secondIdentity ) );

		self::assertSame(
			array(
				'issuer_count'       => 2,
				'registration_count' => 2,
				'consent_count'      => 2,
				'audit_count'        => 2,
			),
			RootKeyProofState::sanitizedEvidence()
		);
	}

	/**
	 * Verifies that every effective WordPress scheme is authoritative.
	 *
	 * @since 0.1.0
	 *
	 * @dataProvider effectiveWordPressSchemeProvider
	 *
	 * @param string $changedScheme The one scheme changed in phase B.
	 */
	public function testEachEffectiveWordPressSchemeIsIndividuallyAuthoritative( string $changedScheme ): void {
		$this->installDeterministicSaltFilter();
		$identity     = self::enabledIdentity( 'single-scheme-' . str_replace( '_', '-', $changedScheme ) . '.example.org' );
		$phaseASource = EffectiveRootKeySource::fromWordPress();
		$oldProof     = self::proofPlaceholder( 'credential', 'single-scheme-' . $changedScheme );

		self::assertTrue( self::issueAccessProof( $oldProof, $phaseASource, $identity ) );

		$this->wordpressPhase         = 'phase-b';
		$this->changedWordPressScheme = $changedScheme;
		$phaseBSource                 = EffectiveRootKeySource::fromWordPress();

		self::assertFalse( $phaseASource->sameRootAs( $phaseBSource ), 'One effective scheme did not affect the root input.' );
		self::assertFalse( self::acceptsAccessProof( $oldProof, $phaseBSource, $identity ) );
		self::assertSame( SiteIssuerLifecycle::ENABLED, SiteIssuerLifecycle::stateFor( $identity->issuer() ) );
		self::assertSame( 0, ExplicitKeyGuard::adoptionCount() );

		$newProof = self::proofPlaceholder( 'credential', 'single-scheme-new-' . $changedScheme );

		self::assertTrue( self::issueAccessProof( $newProof, $phaseBSource, $identity ) );
		self::assertTrue( self::acceptsAccessProof( $newProof, $phaseBSource, $identity ) );
	}

	/**
	 * Supplies each effective WordPress salt scheme independently.
	 *
	 * @since 0.1.0
	 *
	 * @return array<string, array{string}> Scheme cases.
	 */
	public function effectiveWordPressSchemeProvider(): array {
		return array(
			'auth'        => array( 'auth' ),
			'secure auth' => array( 'secure_auth' ),
			'logged in'   => array( 'logged_in' ),
			'nonce'       => array( 'nonce' ),
		);
	}

	/**
	 * Verifies fail-closed explicit mismatch, restore, adoption, and no resurrection.
	 *
	 * @since 0.1.0
	 */
	public function testExplicitKeyMismatchIsReadOnlyAndRestoreOrAdoptionPreservesRequiredState(): void {
		$identity = self::enabledIdentity( 'explicit-root.example.org' );
		RootKeyProofState::seedSentinels( $identity->issuer() );

		$explicitA = self::proofPlaceholder( 'explicit-root', 'a' );
		$explicitB = self::proofPlaceholder( 'explicit-root', 'b' );
		$sourceA   = EffectiveRootKeySource::fromExplicitSnapshot( $explicitA );
		$sourceB   = EffectiveRootKeySource::fromExplicitSnapshot( $explicitB );
		$oldProof  = self::proofPlaceholder( 'credential', 'explicit-a-old' );

		self::assertTrue( ExplicitKeyGuard::establish( $sourceA ) );
		self::assertSame( ExplicitKeyGuard::MATCHING, ExplicitKeyGuard::statusFor( $sourceA ) );
		self::assertTrue( self::issueAccessProof( $oldProof, $sourceA, $identity ) );

		$credentialState = DigestedProofCredentialStore::stateFingerprint();
		$guardState      = ExplicitKeyGuard::stateFingerprint();
		$lifecycleState  = SiteIssuerLifecycle::stateFingerprint();
		$sentinelState   = RootKeyProofState::stateFingerprint();
		$rejectedProof   = self::proofPlaceholder( 'credential', 'explicit-b-rejected' );

		self::assertSame( ExplicitKeyGuard::MISMATCH, ExplicitKeyGuard::statusFor( $sourceB ) );
		self::assertFalse( self::acceptsAccessProof( $oldProof, $sourceB, $identity ) );
		self::assertFalse( self::issueAccessProof( $rejectedProof, $sourceB, $identity ) );
		self::assertTrue(
			hash_equals( $credentialState, DigestedProofCredentialStore::stateFingerprint() ),
			'Explicit mismatch mutated credential proof state.'
		);
		self::assertTrue(
			hash_equals( $guardState, ExplicitKeyGuard::stateFingerprint() ),
			'Explicit mismatch mutated guard proof state.'
		);
		self::assertTrue(
			hash_equals( $lifecycleState, SiteIssuerLifecycle::stateFingerprint() ),
			'Explicit mismatch mutated lifecycle proof state.'
		);
		self::assertTrue(
			hash_equals( $sentinelState, RootKeyProofState::stateFingerprint() ),
			'Explicit mismatch mutated non-credential proof state.'
		);

		self::assertSame( ExplicitKeyGuard::MATCHING, ExplicitKeyGuard::statusFor( $sourceA ) );
		self::assertTrue( self::acceptsAccessProof( $oldProof, $sourceA, $identity ) );
		self::assertTrue( hash_equals( $credentialState, DigestedProofCredentialStore::stateFingerprint() ) );
		self::assertTrue( hash_equals( $guardState, ExplicitKeyGuard::stateFingerprint() ) );
		self::assertTrue( hash_equals( $lifecycleState, SiteIssuerLifecycle::stateFingerprint() ) );
		self::assertTrue( hash_equals( $sentinelState, RootKeyProofState::stateFingerprint() ) );

		self::assertTrue( ExplicitKeyGuard::adoptReplacement( $sourceB ) );
		self::assertSame( ExplicitKeyGuard::MISMATCH, ExplicitKeyGuard::statusFor( $sourceA ) );
		self::assertSame( ExplicitKeyGuard::MATCHING, ExplicitKeyGuard::statusFor( $sourceB ) );
		self::assertSame( 1, ExplicitKeyGuard::credentialGeneration() );
		self::assertSame( 1, ExplicitKeyGuard::adoptionCount() );
		self::assertFalse( self::acceptsAccessProof( $oldProof, $sourceA, $identity ) );
		self::assertFalse( self::acceptsAccessProof( $oldProof, $sourceB, $identity ) );
		self::assertTrue( hash_equals( $credentialState, DigestedProofCredentialStore::stateFingerprint() ) );
		self::assertFalse( hash_equals( $guardState, ExplicitKeyGuard::stateFingerprint() ) );
		self::assertTrue( hash_equals( $lifecycleState, SiteIssuerLifecycle::stateFingerprint() ) );
		self::assertTrue( hash_equals( $sentinelState, RootKeyProofState::stateFingerprint() ) );
		self::assertSame( SiteIssuerLifecycle::ENABLED, SiteIssuerLifecycle::stateFor( $identity->issuer() ) );
		self::assertTrue( RootKeyProofState::sentinelsIntactFor( $identity->issuer() ) );

		$newProof = self::proofPlaceholder( 'credential', 'explicit-b-new' );

		self::assertTrue( self::issueAccessProof( $newProof, $sourceB, $identity ) );
		self::assertTrue( self::acceptsAccessProof( $newProof, $sourceB, $identity ) );
		self::assertFalse(
			DigestedProofCredentialStore::persistedStateContains( $explicitA ),
			'An explicit root snapshot appeared in persistence.'
		);
		self::assertFalse(
			DigestedProofCredentialStore::persistedStateContains( $explicitB ),
			'An explicit root snapshot appeared in persistence.'
		);

		$guardAfterAdoption     = ExplicitKeyGuard::stateFingerprint();
		$credentialsAfterIssue  = DigestedProofCredentialStore::stateFingerprint();
		$lifecycleAfterAdoption = SiteIssuerLifecycle::stateFingerprint();
		$sentinelsAfterAdoption = RootKeyProofState::stateFingerprint();

		self::assertSame( ExplicitKeyGuard::MISMATCH, ExplicitKeyGuard::statusFor( $sourceA ) );
		self::assertFalse( self::acceptsAccessProof( $oldProof, $sourceA, $identity ) );
		self::assertFalse( self::issueAccessProof( $rejectedProof, $sourceA, $identity ) );
		self::assertTrue( hash_equals( $guardAfterAdoption, ExplicitKeyGuard::stateFingerprint() ) );
		self::assertTrue( hash_equals( $credentialsAfterIssue, DigestedProofCredentialStore::stateFingerprint() ) );
		self::assertTrue( hash_equals( $lifecycleAfterAdoption, SiteIssuerLifecycle::stateFingerprint() ) );
		self::assertTrue( hash_equals( $sentinelsAfterAdoption, RootKeyProofState::stateFingerprint() ) );

		self::assertTrue( ExplicitKeyGuard::adoptReplacement( $sourceA ) );
		self::assertSame( ExplicitKeyGuard::MATCHING, ExplicitKeyGuard::statusFor( $sourceA ) );
		self::assertSame( 2, ExplicitKeyGuard::credentialGeneration() );
		self::assertSame( 2, ExplicitKeyGuard::adoptionCount() );
		self::assertFalse(
			self::acceptsAccessProof( $oldProof, $sourceA, $identity ),
			'Re-adopting an earlier explicit key resurrected its pre-adoption credential.'
		);
		self::assertTrue( hash_equals( $credentialsAfterIssue, DigestedProofCredentialStore::stateFingerprint() ) );
		self::assertTrue( hash_equals( $lifecycleAfterAdoption, SiteIssuerLifecycle::stateFingerprint() ) );
		self::assertTrue( hash_equals( $sentinelsAfterAdoption, RootKeyProofState::stateFingerprint() ) );
	}

	/**
	 * Installs a deterministic effective-value filter without retaining values.
	 *
	 * @since 0.1.0
	 */
	private function installDeterministicSaltFilter(): void {
		$this->saltFilter = function ( string $salt, string $scheme ): string {
			unset( $salt );
			$this->observedWordPressSchemes[] = $scheme;

			$phase = null === $this->changedWordPressScheme || $this->changedWordPressScheme === $scheme
				? $this->wordpressPhase
				: 'phase-a';

			return self::wordpressSaltPlaceholder( $phase, $scheme );
		};

		add_filter( 'salt', $this->saltFilter, PHP_INT_MAX, 2 );
	}

	/**
	 * Creates and enables one origin-addressed site issuer.
	 *
	 * @since 0.1.0
	 *
	 * @param string $domain Public proof domain.
	 * @return IssuerIdentity The enabled identity.
	 */
	private static function enabledIdentity( string $domain ): IssuerIdentity {
		$identity = IssuerIdentity::forSite( self::createOriginAddressedSite( $domain ) );

		SiteIssuerLifecycle::prepare( $identity );
		self::assertTrue( SiteIssuerLifecycle::recordVerification( $identity->issuer() ) );
		self::assertTrue( SiteIssuerLifecycle::enable( $identity->issuer() ) );

		return $identity;
	}

	/**
	 * Issues one access proof through the disposable store's public seam.
	 *
	 * @since 0.1.0
	 *
	 * @param string                 $proof Opaque proof placeholder.
	 * @param EffectiveRootKeySource $source Current root snapshot.
	 * @param IssuerIdentity         $identity Exact issuer identity.
	 * @return bool Whether issuance succeeded.
	 */
	private static function issueAccessProof(
		string $proof,
		EffectiveRootKeySource $source,
		IssuerIdentity $identity
	): bool {
		return DigestedProofCredentialStore::issue(
			$proof,
			$source,
			$identity,
			$identity->issuer(),
			'access'
		);
	}

	/**
	 * Validates one access proof through the disposable store's public seam.
	 *
	 * @since 0.1.0
	 *
	 * @param string                 $proof Opaque proof placeholder.
	 * @param EffectiveRootKeySource $source Current root snapshot.
	 * @param IssuerIdentity         $identity Exact issuer identity.
	 * @return bool Whether validation succeeded.
	 */
	private static function acceptsAccessProof(
		string $proof,
		EffectiveRootKeySource $source,
		IssuerIdentity $identity
	): bool {
		return DigestedProofCredentialStore::accepts(
			$proof,
			$source,
			$identity,
			$identity->issuer(),
			'access'
		);
	}

	/**
	 * Creates one supported origin-addressed Multisite site.
	 *
	 * @since 0.1.0
	 *
	 * @param string $domain Public proof domain.
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

	/**
	 * Produces deterministic internal proof material without exposing it.
	 *
	 * @since 0.1.0
	 *
	 * @param string $kind Placeholder category.
	 * @param string $name Placeholder name.
	 * @return string Internal proof material.
	 */
	private static function proofPlaceholder( string $kind, string $name ): string {
		return hash( 'sha256', 'charter-slice0:' . $kind . ':' . $name );
	}

	/**
	 * Produces one deterministic filtered WordPress proof value.
	 *
	 * @since 0.1.0
	 *
	 * @param string $phase Effective-value phase.
	 * @param string $scheme WordPress salt scheme.
	 * @return string Internal effective-value placeholder.
	 */
	private static function wordpressSaltPlaceholder( string $phase, string $scheme ): string {
		return self::proofPlaceholder( 'wordpress-' . $phase, $scheme );
	}
}
