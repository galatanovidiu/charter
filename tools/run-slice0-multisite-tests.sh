#!/usr/bin/env bash

set -euo pipefail

project_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

cd "${project_root}"

cleanup() {
	local exit_code=$?

	trap - EXIT INT TERM

	if (( exit_code != 0 )); then
		npm run test:slice0:multisite:logs || true
	fi

	npm run test:slice0:multisite:destroy || true
	exit "${exit_code}"
}

trap cleanup EXIT INT TERM

export WORDPRESS_BRANCH="${WORDPRESS_BRANCH:-6.9}"
export WP_ENV_CORE="${WP_ENV_CORE:-$(bash tools/resolve-wordpress-core.sh)}"

printf 'Slice 0 WordPress source: %s\n' "${WP_ENV_CORE}"

npm run test:slice0:multisite:destroy >/dev/null 2>&1 || true
npm run test:slice0:multisite:start
npm run test:slice0:multisite:prepare
npm run test:slice0:multisite:version
npm run test:slice0:multisite
npm run test:slice0:root-key

trap - EXIT INT TERM
npm run test:slice0:multisite:destroy
