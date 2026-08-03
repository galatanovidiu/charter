#!/usr/bin/env bash

set -euo pipefail

cleanup() {
	local exit_code=$?

	if (( exit_code != 0 )); then
		npm run test:integration:logs || true
	fi

	npm run test:integration:stop || true
	exit "${exit_code}"
}

trap cleanup EXIT INT TERM

npm run test:integration:start
npm run test:integration

trap - EXIT INT TERM
npm run test:integration:stop
