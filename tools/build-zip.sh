#!/usr/bin/env bash

set -euo pipefail

project_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
archive_path="${project_root}/build/charter.zip"

cd "${project_root}"
mkdir -p build

# dist-archive updates an existing ZIP and can retain files excluded since the
# previous build, so every build starts from an absent target.
rm -f "${archive_path}"

vendor/bin/wp dist-archive . "${archive_path}" \
	--create-target-dir \
	--force \
	--plugin-dirname=charter

php tools/normalize-archive.php "${archive_path}"
