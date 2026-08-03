<?php
/**
 * Normalizes distributable ZIP timestamps for reproducible builds.
 *
 * @package GalatanOvidiu\Charter
 */

declare(strict_types=1);

const CHARTER_ARCHIVE_TIMESTAMP = 946684800;

putenv( 'TZ=UTC' );
date_default_timezone_set( 'UTC' );

$archivePath = $argv[1] ?? '';

if ( '' === $archivePath || ! is_file( $archivePath ) ) {
	fwrite( STDERR, "Pass the path to an existing ZIP file.\n" );
	exit( 1 );
}

$sourceArchive = new ZipArchive();

if ( true !== $sourceArchive->open( $archivePath ) ) {
	fwrite( STDERR, "Cannot open {$archivePath}.\n" );
	exit( 1 );
}

$temporaryPath     = $archivePath . '.normalized-' . bin2hex( random_bytes( 8 ) );
$normalizedArchive = new ZipArchive();

if (
	true !== $normalizedArchive->open(
		$temporaryPath,
		ZipArchive::CREATE | ZipArchive::OVERWRITE
	)
) {
	$sourceArchive->close();
	fwrite( STDERR, "Cannot create a normalized ZIP.\n" );
	exit( 1 );
}

for ( $index = 0; $index < $sourceArchive->numFiles; ++$index ) {
	$entryName = $sourceArchive->getNameIndex( $index );
	$entryData = $sourceArchive->getFromIndex( $index );
	$entryStat = $sourceArchive->statIndex( $index );

	if ( false === $entryName || false === $entryData || false === $entryStat ) {
		$sourceArchive->close();
		$normalizedArchive->close();
		unlink( $temporaryPath );
		fwrite( STDERR, "Cannot read ZIP entry {$index}.\n" );
		exit( 1 );
	}

	$isDirectory = str_ends_with( $entryName, '/' );
	$entryAdded  = $isDirectory
		? $normalizedArchive->addEmptyDir( rtrim( $entryName, '/' ) )
		: $normalizedArchive->addFromString( $entryName, $entryData );

	if ( ! $entryAdded ) {
		$sourceArchive->close();
		$normalizedArchive->close();
		unlink( $temporaryPath );
		fwrite( STDERR, "Cannot add normalized ZIP entry {$entryName}.\n" );
		exit( 1 );
	}

	$compressionMethod = $entryStat['comp_method'] ?? ZipArchive::CM_DEFAULT;

	if (
		! $normalizedArchive->setCompressionName( $entryName, $compressionMethod )
		|| ! $normalizedArchive->setMtimeName( $entryName, CHARTER_ARCHIVE_TIMESTAMP )
	) {
		$sourceArchive->close();
		$normalizedArchive->close();
		unlink( $temporaryPath );
		fwrite( STDERR, "Cannot normalize ZIP entry {$entryName}.\n" );
		exit( 1 );
	}

	$operatingSystem = 0;
	$attributes      = 0;

	if (
		$sourceArchive->getExternalAttributesIndex( $index, $operatingSystem, $attributes )
		&& ! $normalizedArchive->setExternalAttributesName(
			$entryName,
			$operatingSystem,
			$attributes
		)
	) {
		$sourceArchive->close();
		$normalizedArchive->close();
		unlink( $temporaryPath );
		fwrite( STDERR, "Cannot preserve ZIP attributes for {$entryName}.\n" );
		exit( 1 );
	}
}

$sourceArchive->close();

if ( ! $normalizedArchive->close() || ! rename( $temporaryPath, $archivePath ) ) {
	if ( is_file( $temporaryPath ) ) {
		unlink( $temporaryPath );
	}

	fwrite( STDERR, "Cannot save normalized ZIP {$archivePath}.\n" );
	exit( 1 );
}
