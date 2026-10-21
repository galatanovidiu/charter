#!/usr/bin/env bash

set -euo pipefail

project_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
temporary_directory="$(mktemp -d "${TMPDIR:-/tmp}/charter-artifact-allowlist.XXXXXX")"
fixture_archive="${temporary_directory}/charter-unknown-file.zip"

cleanup() {
	local exit_code=$?

	if [[ "${temporary_directory}" == */charter-artifact-allowlist.* ]]; then
		find "${temporary_directory}" -type f -delete
		find "${temporary_directory}" -depth -type d -exec rmdir {} \; 2>/dev/null || true
	fi

	exit "${exit_code}"
}

trap cleanup EXIT INT TERM

cd "${project_root}"
cp build/charter.zip "${fixture_archive}"
php -r '
$archive = new ZipArchive();
if ( true !== $archive->open( $argv[1] ) ) {
	exit( 2 );
}
$archive->addEmptyDir( "charter/.ignored-tool-cache" );
$archive->addFromString( "charter/.ignored-tool-cache/globally-ignored.log", "developer output\n" );
foreach ( array( "charter/.ignored-tool-cache/", "charter/.ignored-tool-cache/globally-ignored.log" ) as $entry ) {
	$index = $archive->locateName( $entry );
	if ( false === $index || ! $archive->setMtimeIndex( $index, 946684800 ) ) {
		exit( 3 );
	}
}
$archive->close();
' "${fixture_archive}"
php tools/normalize-archive.php "${fixture_archive}"

if php tools/verify-archive.php "${fixture_archive}" >"${temporary_directory}/verify.out" 2>&1; then
	echo 'Artifact verification accepted a globally ignored developer file.' >&2
	exit 1
fi

if ! grep -q 'not part of the production allowlist' "${temporary_directory}/verify.out"; then
	echo 'Artifact verification failed for the wrong reason.' >&2
	cat "${temporary_directory}/verify.out" >&2
	exit 1
fi

echo 'Artifact allowlist rejection check passed.'
