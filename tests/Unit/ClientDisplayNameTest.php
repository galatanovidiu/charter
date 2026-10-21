<?php
/**
 * Client display-name safety tests.
 *
 * @package GalatanOvidiu\Charter
 */

declare(strict_types=1);

namespace GalatanOvidiu\Charter\Tests\Unit;

use GalatanOvidiu\Charter\OAuth\ClientDisplayName;
use PHPUnit\Framework\TestCase;

/** Proves consent display names reject unsafe characters before normalization. */
final class ClientDisplayNameTest extends TestCase {

	/** Verifies harmless surrounding spaces remain normalizable. */
	public function testNormalizesSurroundingSpaces(): void {
		self::assertSame( 'Safe client', ClientDisplayName::normalize( '  Safe client  ' ) );
	}

	/**
	 * Verifies trimming cannot hide a prohibited control character.
	 *
	 * @param string $name Candidate display name.
	 *
	 * @dataProvider edgeControlProvider
	 */
	public function testRejectsControlCharactersAtNameEdges( string $name ): void {
		self::assertNull( ClientDisplayName::normalize( $name ) );
	}

	/**
	 * Returns control characters that PHP trim would otherwise remove.
	 *
	 * @return array<string, array{string}>
	 */
	public function edgeControlProvider(): array {
		return array(
			'leading NUL'      => array( "\0Safe client" ),
			'trailing tab'     => array( "Safe client\t" ),
			'trailing newline' => array( "Safe client\n" ),
		);
	}
}
