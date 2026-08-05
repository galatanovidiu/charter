#!/usr/bin/env bash

set -euo pipefail

project_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
timeout_command="$(command -v gtimeout || command -v timeout || true)"
p5_wp_env_started=false

if [[ -z "${timeout_command}" ]]; then
	printf 'P5 CI runner requires GNU timeout or gtimeout.\n' >&2
	exit 1
fi

cd "${project_root}"

destroy_wordpress() {
	"${timeout_command}" --signal=TERM --kill-after=5 30 npm run test:slice0:multisite:destroy >/dev/null 2>&1
}

cleanup() {
	local exit_code=$?
	local cleanup_failed=false

	trap '' INT TERM
	trap - EXIT

	if [[ true == "${p5_wp_env_started}" ]] && ! destroy_wordpress; then
		cleanup_failed=true
	fi

	if [[ true == "${cleanup_failed}" ]]; then
		printf '{"status":"failed","phase":"cleanup","reason_code":"incomplete_cleanup"}\n' >&2
		exit_code=70
	fi

	exit "${exit_code}"
}

trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

export WORDPRESS_BRANCH="6.9"
export WP_ENV_CORE="https://downloads.w.org/release/wordpress-6.9.5.zip"

printf 'Slice 0 P5 WordPress source: %s\n' "${WP_ENV_CORE}"

npm run test:slice0:discovery-publication
destroy_wordpress || true
p5_wp_env_started=true
npm run test:slice0:multisite:start
npm run test:slice0:multisite:prepare
npm run test:slice0:multisite:version
npm run test:slice0:discovery-publication:wordpress:single
npm run test:slice0:discovery-publication:wordpress:multisite

set +e
p5_cli_output="$(npm run --silent test:slice0:discovery-publication:wp-cli 2>&1)"
p5_cli_exit=$?
set -e

if [[ 1 -ne "${p5_cli_exit}" ]] || [[ "${p5_cli_output}" != *'Charter cannot enable OAuth for Canonical public OAuth base URL https://path-network.charter.test/team; v1 requires a bare origin without a path.'* ]]; then
	printf 'P5 WP-CLI diagnostic mismatch.\n' >&2
	exit 1
fi

printf '{"surface":"wp_cli","reason_code":"unsupported_path_topology","exit_code":1,"message_match":true}\n'

npm run test:slice0:discovery-publication:matrix

set +e
p5_cleanup_output="$(npm run --silent test:slice0:discovery-publication:matrix -- --cleanup-probe 2>&1)"
p5_cleanup_exit=$?
set -e

if [[ 79 -ne "${p5_cleanup_exit}" ]] || [[ "${p5_cleanup_output}" != *'{"cleanup_probe":"lane_interrupted","expected_exit":79}'* ]]; then
	printf 'P5 interruption cleanup probe did not reach its exact failure boundary.\n' >&2
	exit 1
fi

if docker ps -a --format '{{.Label "com.docker.compose.project"}}' | rg --quiet '^charter-p5-'; then
	printf 'P5 interruption cleanup probe left a container behind.\n' >&2
	exit 1
fi

if find /tmp -maxdepth 1 -type d -name 'charter-p5-discovery.*' -print -quit | rg --quiet '.'; then
	printf 'P5 interruption cleanup probe left private proof material behind.\n' >&2
	exit 1
fi

printf '{"cleanup_probe":"passed","lane_interrupted":true,"containers_remaining":0,"private_directories_remaining":0}\n'
