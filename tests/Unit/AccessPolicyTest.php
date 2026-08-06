<?php
/**
 * OAuth access policy unit tests.
 *
 * @package GalatanOvidiu\Charter
 */

declare(strict_types=1);

namespace GalatanOvidiu\Charter\Tests\Unit;

use GalatanOvidiu\Charter\OAuth\AccessPolicy;
use PHPUnit\Framework\TestCase;

/**
 * Tests exact protected-resource and specialized-scope registration.
 *
 * @since 0.1.0
 */
final class AccessPolicyTest extends TestCase {

	private const ISSUER   = 'https://site.example.org';
	private const RESOURCE = self::ISSUER . '/wp-json/example-mcp/v1';

	/** Verifies the default origin retains only the general access scope. */
	public function testDefaultResourceRetainsGeneralScope(): void {
		$policy = new AccessPolicy( self::ISSUER );

		self::assertSame( array( AccessPolicy::GENERAL_SCOPE ), $policy->scopeIdentifiers() );
		self::assertSame( array( AccessPolicy::GENERAL_SCOPE ), $policy->scopesForResource( self::ISSUER ) );
		self::assertSame( AccessPolicy::GENERAL_SCOPE, $policy->canonicalScope( self::ISSUER, array( AccessPolicy::GENERAL_SCOPE ) ) );
		self::assertTrue( $policy->bindingAvailable( self::ISSUER, AccessPolicy::GENERAL_SCOPE ) );
	}

	/** Verifies one namespaced scope is associated only with its exact resource. */
	public function testSpecializedScopeRequiresOwnedExactResource(): void {
		$policy = new AccessPolicy( self::ISSUER );

		self::assertTrue( $policy->registerResource( 'example-mcp', self::RESOURCE ) );
		self::assertTrue(
			$policy->registerScope(
				'example-mcp',
				'example-mcp:access',
				'Example MCP access',
				'Use the Example MCP server as your WordPress account.',
				array( self::RESOURCE )
			)
		);

		self::assertSame( array( 'example-mcp:access' ), $policy->scopesForResource( self::RESOURCE ) );
		self::assertSame( 'example-mcp:access', $policy->canonicalScope( self::RESOURCE, array( 'example-mcp:access' ) ) );
		self::assertNull( $policy->canonicalScope( self::ISSUER, array( 'example-mcp:access' ) ) );
		self::assertNull( $policy->canonicalScope( self::RESOURCE, array( AccessPolicy::GENERAL_SCOPE ) ) );
		self::assertTrue( $policy->assignmentAvailable( self::RESOURCE, array( 'example-mcp:access' ) ) );

		$definitions = $policy->consentScopes( 'example-mcp:access' );
		self::assertCount( 1, $definitions );
		self::assertSame( 'Example MCP access', $definitions[0]->name() );
		self::assertSame( 'Use the Example MCP server as your WordPress account.', $definitions[0]->description() );
	}

	/** Verifies collisions and cross-owner associations preserve the first registration. */
	public function testScopeCollisionsAndCrossOwnerAssociationsAreRejected(): void {
		$policy = new AccessPolicy( self::ISSUER );

		self::assertTrue( $policy->registerResource( 'example-mcp', self::RESOURCE ) );
		self::assertTrue(
			$policy->registerScope(
				'example-mcp',
				'example-mcp:access',
				'First name',
				'First consent description.',
				array( self::RESOURCE )
			)
		);
		self::assertFalse(
			$policy->registerScope(
				'example-mcp',
				'example-mcp:access',
				'Replacement name',
				'Replacement consent description.',
				array( self::RESOURCE )
			)
		);
		self::assertFalse(
			$policy->registerScope(
				'other-plugin',
				'other-plugin:access',
				'Other access',
				'Cross-owner resource association.',
				array( self::RESOURCE )
			)
		);
		self::assertSame( 'First name', $policy->consentScopes( 'example-mcp:access' )[0]->name() );
		self::assertSame( array( 'example-mcp:access' ), $policy->scopesForResource( self::RESOURCE ) );
	}

	/** Verifies malformed namespace and cross-issuer resource claims fail closed. */
	public function testInvalidNamespaceResourceAndConsentRegistrationsAreRejected(): void {
		$policy = new AccessPolicy( self::ISSUER );

		self::assertFalse( $policy->registerResource( 'example-mcp', 'https://sibling.example.org/wp-json/example-mcp/v1' ) );
		self::assertFalse( $policy->registerResource( 'example-mcp', self::ISSUER ) );
		self::assertFalse( $policy->registerResource( 'example-mcp', self::RESOURCE . '?mode=wide' ) );
		self::assertFalse( $policy->registerResource( 'example-mcp', self::ISSUER . '/wp-json/../admin' ) );
		self::assertFalse( $policy->registerResource( 'example-mcp', self::ISSUER . '/wp-json//example-mcp' ) );
		self::assertFalse( $policy->registerResource( 'example-mcp', self::ISSUER . '/wp-json/%65xample-mcp' ) );
		self::assertTrue( $policy->registerResource( 'example-mcp', self::RESOURCE ) );
		self::assertFalse( $policy->registerScope( 'example-mcp', 'other:access', 'Wrong namespace', 'Wrong namespace.', array( self::RESOURCE ) ) );
		self::assertFalse( $policy->registerScope( 'example-mcp', 'example-mcp:access', '', 'Missing name.', array( self::RESOURCE ) ) );
		self::assertFalse( $policy->registerScope( 'example-mcp', 'example-mcp:access', 'Missing description', '', array( self::RESOURCE ) ) );
		self::assertFalse( $policy->bindingAvailable( self::RESOURCE, 'example-mcp:access' ) );
	}

	/** Verifies a provider that stops registering leaves no reusable authority. */
	public function testFreshPolicyFailsClosedWhenProviderNoLongerRegisters(): void {
		$registered = new AccessPolicy( self::ISSUER );
		self::assertTrue( $registered->registerResource( 'example-mcp', self::RESOURCE ) );
		self::assertTrue( $registered->registerScope( 'example-mcp', 'example-mcp:access', 'MCP access', 'Use the MCP server.', array( self::RESOURCE ) ) );
		self::assertTrue( $registered->bindingAvailable( self::RESOURCE, 'example-mcp:access' ) );

		$providerMissing = new AccessPolicy( self::ISSUER );
		self::assertFalse( $providerMissing->hasResource( self::RESOURCE ) );
		self::assertFalse( $providerMissing->bindingAvailable( self::RESOURCE, 'example-mcp:access' ) );
	}

	/** Verifies an isolated resource may explicitly opt into general access. */
	public function testIsolatedResourceMayExplicitlySupportGeneralScope(): void {
		$policy = new AccessPolicy( self::ISSUER );

		self::assertTrue( $policy->registerResource( 'example-mcp', self::RESOURCE, true ) );
		self::assertSame( array( AccessPolicy::GENERAL_SCOPE ), $policy->scopesForResource( self::RESOURCE ) );
		self::assertTrue( $policy->bindingAvailable( self::RESOURCE, AccessPolicy::GENERAL_SCOPE ) );
		self::assertSame( array( self::ISSUER, self::RESOURCE ), $policy->consentScopes( AccessPolicy::GENERAL_SCOPE )[0]->resources() );
	}
}
