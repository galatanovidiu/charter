#!/usr/bin/env bash

set -euo pipefail

project_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
mode="${1:-}"
run_id="$(openssl rand -hex 8)"
runner_pid='-'
runtime_directory="$(mktemp -d "${TMPDIR:-/tmp}/charter-p2-rest-auth.XXXXXXXX")"
stdout_file="${runtime_directory}/runner.stdout"
stderr_file="${runtime_directory}/runner.stderr"
timeout_command="$(command -v gtimeout || command -v timeout || true)"

case "${mode}" in
	process)
		runner_file='ProcessRunner.php'
		;;
	http)
		runner_file='HttpRunner.php'
		;;
	*)
		php "${project_root}/tools/validate-slice0-rest-authentication-output.php" process </dev/null || true
		exit 1
		;;
esac

cleanup_owned_users() {
	(
		cd "${project_root}"
		"${timeout_command}" --signal=TERM --kill-after=5 30 npm exec -- wp-env run cli \
			--config=.wp-env.slice0.json \
			--env-cwd=wp-content/plugins/charter \
			env CHARTER_P2_RUN_ID="${run_id}" wp eval \
			'$args = array( (string) getenv( "CHARTER_P2_RUN_ID" ) ); require "tests/fixtures/rest-authentication-boundary/CleanupWorker.php";'
	) >/dev/null 2>&1 || true
}

cleanup() {
	local exit_code=$?

	trap - EXIT INT TERM
	if [[ "${runner_pid}" != '-' ]]; then
		kill "${runner_pid}" >/dev/null 2>&1 || true
		wait "${runner_pid}" 2>/dev/null || true
	fi
	cleanup_owned_users
	rm -f "${stdout_file}" "${stderr_file}"
	rmdir "${runtime_directory}" >/dev/null 2>&1 || true
	exit "${exit_code}"
}

trap cleanup EXIT
trap 'exit 124' INT TERM

if [[ -z "${timeout_command}" ]]; then
	php "${project_root}/tools/validate-slice0-rest-authentication-output.php" "${mode}" </dev/null || true
	exit 1
fi

(
	cd "${project_root}"
	"${timeout_command}" --signal=TERM --kill-after=5 180 npm exec -- wp-env run cli \
		--config=.wp-env.slice0.json \
		--env-cwd=wp-content/plugins/charter \
		env CHARTER_P2_RUN_ID="${run_id}" CHARTER_P2_RUNNER_FILE="${runner_file}" wp eval \
		'$args = array( (string) getenv( "CHARTER_P2_RUN_ID" ) ); require "tests/fixtures/rest-authentication-boundary/" . basename( (string) getenv( "CHARTER_P2_RUNNER_FILE" ) );'
) >"${stdout_file}" 2>"${stderr_file}" &
runner_pid=$!

set +e
wait "${runner_pid}"
runner_exit=$?
set -e
runner_pid='-'

set +e
{
	command cat "${stdout_file}"
	command cat "${stderr_file}"
} | php "${project_root}/tools/validate-slice0-rest-authentication-output.php" "${mode}"
validator_exit=$?
set -e

if (( runner_exit != 0 || validator_exit != 0 )); then
	exit 1
fi
