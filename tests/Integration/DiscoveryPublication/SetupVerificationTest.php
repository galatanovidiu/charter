<?php
/**
 * Slice 0 setup presentation and verification tests.
 *
 * @package GalatanOvidiu\Charter
 */

declare(strict_types=1);

namespace GalatanOvidiu\Charter\Tests\Integration\DiscoveryPublication;

use GalatanOvidiu\Charter\Tests\Prototype\DiscoveryPublication\SetupPresentation;
use GalatanOvidiu\Charter\Tests\Prototype\DiscoveryPublication\VerificationLedger;
use PHPUnit\Framework\TestCase;

/**
 * Proves exact setup guidance and per-issuer verification isolation.
 *
 * @since 0.1.0
 */
final class SetupVerificationTest extends TestCase {

	/**
	 * Verifies exact non-secret browser, curl, and real-client guidance.
	 *
	 * @since 0.1.0
	 */
	public function testPresentsExactExternalVerificationInstructions(): void {
		$issuer   = 'https://issuer.charter.test';
		$resource = $issuer . '/integrations/example';

		$presentation = SetupPresentation::forIssuer( $issuer, array( $resource ), false );

		self::assertSame( $issuer, $presentation['issuer'] );
		self::assertSame(
			array(
				$issuer . '/.well-known/oauth-authorization-server',
				$issuer . '/.well-known/oauth-protected-resource',
				$issuer . '/.well-known/oauth-protected-resource/integrations/example',
			),
			$presentation['verification_urls']
		);
		self::assertSame( 200, $presentation['expected']['status'] );
		self::assertSame( 'application/json', $presentation['expected']['content_type'] );
		self::assertSame( 'json', $presentation['expected']['body_class'] );
		self::assertFalse( $presentation['expected']['redirect'] );
		self::assertSame(
			array(
				$issuer . '/.well-known/oauth-authorization-server'                         => $issuer,
				$issuer . '/.well-known/oauth-protected-resource'                           => $issuer,
				$issuer . '/.well-known/oauth-protected-resource/integrations/example'      => $resource,
			),
			$presentation['expected']['identity_by_url']
		);
		self::assertSame( '*', $presentation['expected']['access_control_allow_origin'] );
		self::assertFalse( $presentation['expected']['access_control_allow_credentials'] );
		self::assertSame( 'no-store', $presentation['expected']['cache_control'] );
		self::assertSame( 'exact requested URL', $presentation['expected']['content_location'] );
		self::assertFalse( $presentation['expected']['backend_reference_present'] );
		self::assertStringContainsString( 'curl --disable', $presentation['curl_command'] );
		self::assertStringContainsString( '--connect-timeout 5', $presentation['curl_command'] );
		self::assertStringContainsString( '--max-time 10', $presentation['curl_command'] );
		self::assertStringNotContainsString( '--location', $presentation['curl_command'] );
		self::assertStringNotContainsString( 'Authorization', $presentation['curl_command'] );
		self::assertStringContainsString( 'MCP Inspector 2.0.0', $presentation['real_client_instructions'] );
		self::assertStringContainsString( 'stop before grant behavior', $presentation['real_client_instructions'] );
		self::assertNull( $presentation['development_warning'] );
	}

	/**
	 * Verifies development wording without claiming production reachability.
	 *
	 * @since 0.1.0
	 */
	public function testDevelopmentPresentationNamesIntendedClientAndWarning(): void {
		$presentation = SetupPresentation::forIssuer(
			'https://issuer.charter.test',
			array(),
			true,
			'MCP Inspector 2.0.0 in the proof browser profile'
		);

		self::assertStringContainsString( 'intended local client', (string) $presentation['development_warning'] );
		self::assertStringContainsString( 'insecure development', (string) $presentation['development_warning'] );
		self::assertStringContainsString( 'MCP Inspector 2.0.0', (string) $presentation['development_warning'] );
		self::assertStringNotContainsString( 'externally reachable', (string) $presentation['development_warning'] );
	}

	/**
	 * Verifies that an established issuer cannot escape the pasted shell assignment.
	 *
	 * @since 0.1.0
	 */
	public function testShellEscapesTheIssuerInOperatorGuidance(): void {
		$issuer       = "https://issuer';id;echo'.charter.test";
		$presentation = SetupPresentation::forIssuer( $issuer );
		$firstLine    = strtok( $presentation['curl_command'], "\n" );

		self::assertSame( 'charter_issuer=' . escapeshellarg( $issuer ), $firstLine );
	}

	/**
	 * Verifies that verification and enablement remain exact per issuer.
	 *
	 * @since 0.1.0
	 */
	public function testRecordsOnlyExactSuccessfulExternalObservationsPerIssuer(): void {
		$verified    = 'https://verified.charter.test';
		$intercepted = 'https://intercepted.charter.test';
		$unverified  = 'https://unverified.charter.test';
		$available   = 'https://available.charter.test';
		$ledger      = new VerificationLedger();

		$ledger->prepare( $verified, array( $verified . '/integrations/example' ) );
		$ledger->prepare( $intercepted );
		$ledger->prepare( $unverified );

		self::assertTrue(
			$ledger->recordVerification(
				$verified,
				'curl',
				self::successfulObservations( $verified, $verified . '/integrations/example' )
			)
		);
		self::assertFalse(
			$ledger->recordVerification(
				$intercepted,
				'browser',
				self::interceptedObservations( $intercepted )
			)
		);

		self::assertTrue( $ledger->enable( $verified ) );
		self::assertFalse( $ledger->enable( $intercepted ) );
		self::assertFalse( $ledger->enable( $unverified ) );
		self::assertFalse( $ledger->enable( $available ) );
		self::assertSame( VerificationLedger::ENABLED, $ledger->stateFor( $verified ) );
		self::assertSame( VerificationLedger::PREPARED, $ledger->stateFor( $intercepted ) );
		self::assertSame( VerificationLedger::PREPARED, $ledger->stateFor( $unverified ) );
		self::assertSame( VerificationLedger::AVAILABLE, $ledger->stateFor( $available ) );
		self::assertSame(
			array(
				'method' => 'curl',
				'result' => 'passed',
			),
			$ledger->verificationFor( $verified )
		);
		self::assertNull( $ledger->verificationFor( $intercepted ) );
	}

	/**
	 * Verifies that every fixed validator result field is required.
	 *
	 * @since 0.1.0
	 */
	public function testRejectsAnyIncompleteOrFailedValidatorResult(): void {
		$issuer       = 'https://verified.charter.test';
		$valid        = self::successfulObservations( $issuer );
		$invalidField = array(
			'status'                             => 500,
			'status_match'                       => false,
			'content_type_class'                 => 'text/html',
			'body_class'                         => 'html',
			'redirect_present'                   => true,
			'identity_match'                     => false,
			'metadata_match'                     => false,
			'access_control_allow_origin'        => 'absent',
			'access_control_credentials_present' => true,
			'cache_class'                        => 'present',
			'canonical_location_match'           => false,
			'front_controller_reached_match'     => false,
			'wordpress_tree_version_match'       => false,
			'backend_reference_present'          => true,
			'verification_accepted'              => false,
		);

		foreach ( $invalidField as $field => $invalidValue ) {
			$ledger = new VerificationLedger();
			$ledger->prepare( $issuer );
			$observations              = $valid;
			$observations[0][ $field ] = $invalidValue;

			self::assertFalse( $ledger->recordVerification( $issuer, 'curl', $observations ), $field );
			self::assertFalse( $ledger->enable( $issuer ), $field );
		}
	}

	/**
	 * Builds exact successful observations for all required URLs.
	 *
	 * @since 0.1.0
	 *
	 * @param string      $issuer            The exact issuer.
	 * @param string|null $protectedResource The isolated resource.
	 * @return list<array<string, bool|int|string>> Observations.
	 */
	private static function successfulObservations( string $issuer, ?string $protectedResource = null ): array {
		$observations = array(
			self::successfulObservation( $issuer . '/.well-known/oauth-authorization-server' ),
			self::successfulObservation( $issuer . '/.well-known/oauth-protected-resource' ),
		);

		if ( null !== $protectedResource ) {
			$observations[] = self::successfulObservation(
				$issuer . '/.well-known/oauth-protected-resource/integrations/example'
			);
		}

		return $observations;
	}

	/**
	 * Builds one exact successful fixed-schema validator result.
	 *
	 * @since 0.1.0
	 *
	 * @param string $url The exact requested URL.
	 * @return array<string, bool|int|string> Observation.
	 */
	private static function successfulObservation( string $url ): array {
		return array(
			'requested_url'                      => $url,
			'status'                             => 200,
			'status_match'                       => true,
			'content_type_class'                 => 'application/json',
			'body_class'                         => 'json',
			'redirect_present'                   => false,
			'identity_match'                     => true,
			'metadata_match'                     => true,
			'access_control_allow_origin'        => '*',
			'access_control_credentials_present' => false,
			'cache_class'                        => 'no-store',
			'canonical_location_match'           => true,
			'front_controller_reached_match'     => true,
			'wordpress_tree_version_match'       => true,
			'backend_reference_present'          => false,
			'verification_accepted'              => true,
		);
	}

	/**
	 * Builds intercepted fixed-schema observations for the two issuer URLs.
	 *
	 * @since 0.1.0
	 *
	 * @param string $issuer The exact issuer.
	 * @return list<array<string, bool|int|string>> Observations.
	 */
	private static function interceptedObservations( string $issuer ): array {
		$observations    = self::successfulObservations( $issuer );
		$observations[0] = array_merge(
			$observations[0],
			array(
				'status'                => 302,
				'status_match'          => false,
				'content_type_class'    => 'text/html',
				'body_class'            => 'html',
				'redirect_present'      => true,
				'identity_match'        => false,
				'metadata_match'        => false,
				'verification_accepted' => false,
			)
		);

		return $observations;
	}
}
