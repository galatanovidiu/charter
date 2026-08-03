#!/usr/bin/env bash

set -euo pipefail

project_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

cd "${project_root}"

npm run build:zip
npm run artifact:verify
(
	cd build
	sha256sum charter.zip >charter.zip.sha256
)
rm -rf build/extracted
unzip -q build/charter.zip -d build/extracted
