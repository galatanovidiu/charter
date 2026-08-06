#!/usr/bin/env bash

set -euo pipefail

project_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
temporary_directory="$(mktemp -d "${TMPDIR:-/tmp}/charter-reproducible-artifact.XXXXXX")"
first_archive="${temporary_directory}/charter-first.zip"

cleanup() {
	local exit_code=$?

	if [[ "${temporary_directory}" == */charter-reproducible-artifact.* ]]; then
		find "${temporary_directory}" -type f -delete
		rmdir "${temporary_directory}" 2>/dev/null || true
	fi

	exit "${exit_code}"
}

trap cleanup EXIT INT TERM

cd "${project_root}"
bash tools/prepare-artifact.sh
cp build/charter.zip "${first_archive}"
bash tools/prepare-artifact.sh

if ! cmp --silent "${first_archive}" build/charter.zip; then
	echo 'Two clean artifact builds produced different ZIP bytes.' >&2
	exit 1
fi

echo "Reproducible artifact check passed: $(sha256sum build/charter.zip | awk '{print $1}')"
