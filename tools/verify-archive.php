<?php
/**
 * Verifies the distributable Charter ZIP.
 *
 * @package GalatanOvidiu\Charter
 */

declare(strict_types=1);

const EXPECTED_PLUGIN_NAME = 'Charter – OAuth 2.1 Authorization Server';
const EXPECTED_DESCRIPTION = 'Provides a secure, standards-compliant OAuth 2.1 authorization server for WordPress.';
const EXPECTED_WORDPRESS    = '6.9';
const EXPECTED_PHP          = '8.4';
const EXPECTED_TEXT_DOMAIN  = 'charter';
const EXPECTED_LICENSE      = 'GPL-2.0-or-later';
const EXPECTED_ARCHIVE_TIME = 946684800;

putenv( 'TZ=UTC' );
date_default_timezone_set( 'UTC' );

/**
 * Reports an artifact verification failure.
 *
 * @param string $message Failure message.
 */
function fail( string $message ): never {
	fwrite( STDERR, "Artifact verification failed: {$message}\n" );
	exit( 1 );
}

/**
 * Removes a temporary directory recursively.
 *
 * @param string $directory Directory to remove.
 */
function removeDirectory( string $directory ): void {
	if ( ! is_dir( $directory ) ) {
		return;
	}

	$items = new RecursiveIteratorIterator(
		new RecursiveDirectoryIterator( $directory, FilesystemIterator::SKIP_DOTS ),
		RecursiveIteratorIterator::CHILD_FIRST
	);

	foreach ( $items as $item ) {
		if ( $item->isDir() ) {
			rmdir( $item->getPathname() );
		} else {
			unlink( $item->getPathname() );
		}
	}

	rmdir( $directory );
}

/**
 * Reads a metadata value from a plugin header or readme file.
 *
 * @param string $contents File contents.
 * @param string $field    Metadata field name.
 *
 * @return string Metadata value.
 */
function metadataValue( string $contents, string $field ): string {
	$pattern = '/^[ \t]*(?:\\*[ \t]*)?' . preg_quote( $field, '/' ) . ':[ \t]*(.+?)[ \t]*$/mi';

	if ( 1 !== preg_match( $pattern, $contents, $matches ) ) {
		fail( "Missing {$field} metadata." );
	}

	return trim( $matches[1] );
}

/**
 * Validates and splits a canonical ZIP entry name.
 *
 * @param string $entry ZIP entry name.
 *
 * @return array<int, string> Path segments.
 */
function archiveEntrySegments( string $entry ): array {
	if (
		'' === $entry
		|| str_contains( $entry, '\\' )
		|| 1 === preg_match( '/[\x00-\x1F\x7F]/', $entry )
	) {
		fail( "Non-canonical ZIP entry name: {$entry}" );
	}

	$isDirectory = str_ends_with( $entry, '/' );
	$path        = $isDirectory ? substr( $entry, 0, -1 ) : $entry;
	$segments    = explode( '/', $path );

	if ( '' === $path ) {
		fail( "Non-canonical ZIP entry name: {$entry}" );
	}

	foreach ( $segments as $segment ) {
		if ( '' === $segment || '.' === $segment || '..' === $segment ) {
			fail( "Non-canonical ZIP entry name: {$entry}" );
		}
	}

	$canonicalEntry = implode( '/', $segments ) . ( $isDirectory ? '/' : '' );

	if ( $canonicalEntry !== $entry ) {
		fail( "Non-canonical ZIP entry name: {$entry}" );
	}

	if ( 'charter' !== $segments[0] || ( 1 === count( $segments ) && ! $isDirectory ) ) {
		fail( "Unexpected top-level entry: {$entry}" );
	}

	return $segments;
}

$archivePath = $argv[1] ?? '';

if ( '' === $archivePath || ! is_file( $archivePath ) ) {
	fail( 'Pass the path to an existing ZIP file.' );
}

$archive = new ZipArchive();

if ( true !== $archive->open( $archivePath ) ) {
	fail( "Cannot open {$archivePath}." );
}

$entries           = array();
$forbiddenSegments = array(
	'.agents',
	'.git',
	'.github',
	'.wordpress-org',
	'build',
	'docs',
	'node_modules',
	'tests',
	'tools',
	'vendor',
);
$forbiddenFiles    = array(
	'.distignore',
	'.editorconfig',
	'.gitignore',
	'.npmrc',
	'.nvmrc',
	'.prettierignore',
	'.prettierrc.cjs',
	'.DS_Store',
	'CHANGELOG.md',
	'CONTRIBUTING.md',
	'README.md',
	'RELEASING.md',
	'SECURITY.md',
	'composer.json',
	'composer.lock',
	'package.json',
	'package-lock.json',
	'phpcs.xml.dist',
	'phpstan-bootstrap.php',
	'phpstan.neon.dist',
	'phpunit.xml.dist',
);

for ( $index = 0; $index < $archive->numFiles; ++$index ) {
	$entry = $archive->getNameIndex( $index );

	if ( false === $entry ) {
		fail( "Cannot read ZIP entry {$index}." );
	}

	$segments = archiveEntrySegments( $entry );

	if ( in_array( $entry, $entries, true ) ) {
		fail( "Duplicate ZIP entry: {$entry}" );
	}

	$entries[] = $entry;

	$entryMetadata = $archive->statIndex( $index );

	if (
		false === $entryMetadata
		|| ! isset( $entryMetadata['mtime'] )
		|| EXPECTED_ARCHIVE_TIME !== $entryMetadata['mtime']
	) {
		fail( "ZIP entry has a non-reproducible timestamp: {$entry}" );
	}

	$relativeSegments = array_slice( $segments, 1 );
	$relativePath     = implode( '/', $relativeSegments );

	foreach ( $relativeSegments as $segment ) {
		if ( str_starts_with( $segment, '.git' ) ) {
			fail( "Forbidden Git metadata in ZIP: {$entry}" );
		}

		if ( in_array( $segment, $forbiddenSegments, true ) ) {
			fail( "Forbidden directory in ZIP: {$entry}" );
		}

		if ( str_starts_with( $segment, '.wp-env' ) ) {
			fail( "Forbidden wp-env configuration in ZIP: {$entry}" );
		}
	}

	if ( in_array( basename( $relativePath ), $forbiddenFiles, true ) ) {
		fail( "Forbidden development file in ZIP: {$entry}" );
	}

	if ( str_ends_with( basename( $relativePath ), '.local.md' ) ) {
		fail( "Forbidden local instruction file in ZIP: {$entry}" );
	}

	if ( str_ends_with( $relativePath, '.gitkeep' ) ) {
		fail( "Placeholder file must not ship: {$entry}" );
	}
}

$requiredEntries = array(
	'charter/LICENSE',
	'charter/charter.php',
	'charter/readme.txt',
	'charter/uninstall.php',
	'charter/src/Autoloader.php',
	'charter/src/Plugin.php',
	'charter/src/Uninstaller.php',
);

foreach ( $requiredEntries as $requiredEntry ) {
	if ( ! in_array( $requiredEntry, $entries, true ) ) {
		fail( "Missing required file: {$requiredEntry}" );
	}
}

$temporaryDirectory = sys_get_temp_dir() . '/charter-artifact-' . bin2hex( random_bytes( 8 ) );

if ( ! mkdir( $temporaryDirectory, 0700, true ) && ! is_dir( $temporaryDirectory ) ) {
	fail( "Cannot create temporary directory {$temporaryDirectory}." );
}

try {
	if ( ! $archive->extractTo( $temporaryDirectory ) ) {
		fail( 'Cannot extract the ZIP.' );
	}

	$archive->close();

	$pluginRoot    = $temporaryDirectory . '/charter';
	$pluginHeader  = file_get_contents( $pluginRoot . '/charter.php' );
	$pluginReadme  = file_get_contents( $pluginRoot . '/readme.txt' );
	$expectedTag   = getenv( 'EXPECTED_VERSION' );
	$packageJson   = file_get_contents( dirname( __DIR__ ) . '/package.json' );
	$headerVersion = '';

	if ( false === $pluginHeader || false === $pluginReadme || false === $packageJson ) {
		fail( 'Cannot read release metadata files.' );
	}

	$packageMetadata = json_decode( $packageJson, true );

	if (
		! is_array( $packageMetadata )
		|| ! isset( $packageMetadata['version'] )
		|| ! is_string( $packageMetadata['version'] )
	) {
		fail( 'package.json does not declare a version.' );
	}

	$packageVersion = $packageMetadata['version'];

	$metadataPairs = array(
		'Requires at least' => EXPECTED_WORDPRESS,
		'Requires PHP'      => EXPECTED_PHP,
		'License'           => EXPECTED_LICENSE,
		'License URI'       => 'https://www.gnu.org/licenses/gpl-2.0.html',
	);

	foreach ( $metadataPairs as $field => $expectedValue ) {
		$headerValue = metadataValue( $pluginHeader, $field );
		$readmeValue = metadataValue( $pluginReadme, $field );

		if ( $expectedValue !== $headerValue || $expectedValue !== $readmeValue ) {
			fail( "{$field} metadata is not synchronized." );
		}
	}

	if ( EXPECTED_PLUGIN_NAME !== metadataValue( $pluginHeader, 'Plugin Name' ) ) {
		fail( 'Plugin Name metadata is incorrect.' );
	}

	if ( EXPECTED_DESCRIPTION !== metadataValue( $pluginHeader, 'Description' ) ) {
		fail( 'Description metadata is incorrect.' );
	}

	if ( EXPECTED_TEXT_DOMAIN !== metadataValue( $pluginHeader, 'Text Domain' ) ) {
		fail( 'Text Domain metadata is incorrect.' );
	}

	if (
		1 !== preg_match(
			'/^=== ' . preg_quote( EXPECTED_PLUGIN_NAME, '/' ) . ' ===$/m',
			$pluginReadme
		)
	) {
		fail( 'The readme title does not match the plugin name.' );
	}

	if ( ! str_contains( $pluginReadme, "\n" . EXPECTED_DESCRIPTION . "\n" ) ) {
		fail( 'The readme short description does not match the plugin description.' );
	}

	$headerVersion = metadataValue( $pluginHeader, 'Version' );
	$stableTag     = metadataValue( $pluginReadme, 'Stable tag' );

	if ( $headerVersion !== $stableTag ) {
		fail( 'Plugin Version and readme Stable tag differ.' );
	}

	if ( 1 !== preg_match( '/^[0-9]+\\.[0-9]+\\.[0-9]+$/', $packageVersion ) ) {
		fail( 'package.json version must be a bare semantic version.' );
	}

	if ( $packageVersion !== $headerVersion ) {
		fail( "package.json version {$packageVersion} does not match plugin version {$headerVersion}." );
	}

	if ( false === $expectedTag || '' === $expectedTag ) {
		$expectedTag = $packageVersion;
	}

	if ( 1 !== preg_match( '/^[0-9]+\\.[0-9]+\\.[0-9]+$/', $expectedTag ) ) {
		fail( 'EXPECTED_VERSION must be a bare semantic version.' );
	}

	if ( $expectedTag !== $headerVersion ) {
		fail( "Git tag {$expectedTag} does not match plugin version {$headerVersion}." );
	}

	$phpFiles = new RecursiveIteratorIterator(
		new RecursiveDirectoryIterator( $pluginRoot, FilesystemIterator::SKIP_DOTS )
	);

	foreach ( $phpFiles as $phpFile ) {
		if ( 'php' !== strtolower( $phpFile->getExtension() ) ) {
			continue;
		}

		$command = escapeshellarg( PHP_BINARY ) . ' -l ' . escapeshellarg( $phpFile->getPathname() );
		exec( $command . ' 2>&1', $output, $exitCode );

		if ( 0 !== $exitCode ) {
			fail( "PHP lint failed for {$phpFile->getPathname()}: " . implode( "\n", $output ) );
		}

		$output = array();
	}

	echo "Verified {$archivePath}\n";
	echo 'Version: ' . $headerVersion . "\n";
	echo 'SHA-256: ' . hash_file( 'sha256', $archivePath ) . "\n";
} finally {
	removeDirectory( $temporaryDirectory );
}
