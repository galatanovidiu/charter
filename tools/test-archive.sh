#!/usr/bin/env bash

set -euo pipefail

project_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
artifact_config="${project_root}/build/.wp-env.artifact.json"

cd "${project_root}"

if [[ ! -f build/charter.zip ]]; then
	echo "build/charter.zip does not exist. Run npm run build:zip first." >&2
	exit 1
fi

expected_version="${EXPECTED_VERSION:-$(node --print "require('./package.json').version")}"

if [[ ! "${expected_version}" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
	echo "The expected artifact version must be a bare semantic version." >&2
	exit 1
fi

mkdir -p build

cat >"${artifact_config}" <<'JSON'
{
	"$schema": "https://schemas.wp.org/trunk/wp-env.json",
	"core": null,
	"phpVersion": "8.4",
	"testsEnvironment": false,
	"config": {
		"FS_METHOD": "direct",
		"WP_DEBUG": true,
		"WP_DEBUG_LOG": true,
		"WP_DEVELOPMENT_MODE": "plugin"
	},
	"mappings": {
		"wp-content/uploads/charter-artifacts": "./build"
	}
}
JSON

cleanup() {
	local exit_code=$?

	if (( exit_code != 0 )); then
		wp-env logs --config="${artifact_config}" || true
	fi

	wp-env destroy --config="${artifact_config}" --force || true
	exit "${exit_code}"
}

trap cleanup EXIT INT TERM

wp-env destroy --config="${artifact_config}" --force >/dev/null 2>&1 || true
wp-env start --config="${artifact_config}" --auto-port
wp-env run cli --config="${artifact_config}" wp plugin install \
	/var/www/html/wp-content/uploads/charter-artifacts/charter.zip \
	--activate \
	--force
wp-env run cli --config="${artifact_config}" wp plugin is-active charter
wp-env run cli --config="${artifact_config}" env EXPECTED_VERSION="${expected_version}" wp eval '
	$expected_version = getenv( "EXPECTED_VERSION" );

	if (
		! is_string( $expected_version )
		|| ! defined( "CHARTER_VERSION" )
		|| $expected_version !== CHARTER_VERSION
	) {
		throw new RuntimeException( "The activated artifact version is incorrect." );
	}
'
wp-env run cli --config="${artifact_config}" wp plugin install plugin-check --activate
wp-env run cli --config="${artifact_config}" wp plugin check charter \
	--require=/var/www/html/wp-content/plugins/plugin-check/cli.php \
	--format=strict-table \
	--slug=charter

trap - EXIT INT TERM
wp-env destroy --config="${artifact_config}" --force
