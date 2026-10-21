#!/usr/bin/env bash

set -euo pipefail

project_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
archive_path="${project_root}/build/charter.zip"
temporary_directory="$(mktemp -d "${TMPDIR:-/tmp}/charter-production-artifact.XXXXXX")"
staging_root="${temporary_directory}/charter"

cleanup() {
	local exit_code=$?

	if [[ "${temporary_directory}" == */charter-production-artifact.* ]]; then
		find "${temporary_directory}" -type f -delete
		find "${temporary_directory}" -depth -type d -exec rmdir {} \; 2>/dev/null || true
	fi

	exit "${exit_code}"
}

trap cleanup EXIT INT TERM

cd "${project_root}"
mkdir -p build

# dist-archive updates an existing ZIP and can retain files excluded since the
# previous build, so every build starts from an absent target.
rm -f "${archive_path}"

mkdir -p "${staging_root}/src" "${staging_root}/assets/admin" "${staging_root}/assets/css" "${staging_root}/assets/js" "${staging_root}/languages"
cp LICENSE charter.php readme.txt uninstall.php "${staging_root}/"

while IFS= read -r -d '' source_file; do
	relative_path="${source_file#./}"
	mkdir -p "${staging_root}/$(dirname "${relative_path}")"
	cp "${relative_path}" "${staging_root}/${relative_path}"
done < <(find ./src -type f -name '*.php' ! -path '*/.*' -print0)

for runtime_asset in \
	assets/admin/connected-apps.asset.php \
	assets/admin/connected-apps.js \
	assets/admin/network-admin.asset.php \
	assets/admin/network-admin.js \
	assets/admin/site-admin.asset.php \
	assets/admin/site-admin.js \
	assets/css/admin.css \
	assets/js/oauth-consent.js; do
	cp "${runtime_asset}" "${staging_root}/${runtime_asset}"
done

while IFS= read -r -d '' language_file; do
	relative_path="${language_file#./}"
	cp "${relative_path}" "${staging_root}/${relative_path}"
done < <(find ./languages -maxdepth 1 -type f \( -name '*.json' -o -name '*.mo' -o -name '*.po' -o -name '*.pot' \) -print0)

vendor/bin/wp dist-archive "${staging_root}" "${archive_path}" \
	--create-target-dir \
	--force \
	--plugin-dirname=charter

php tools/normalize-archive.php "${archive_path}"
