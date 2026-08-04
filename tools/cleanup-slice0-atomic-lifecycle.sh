#!/usr/bin/env bash

set -euo pipefail

run_id="${1:-}"
database_container="${2:--}"
runtime_container="${3:--}"
network_name="${4:--}"
volume_name="${5:--}"
wordpress_directory="${6:--}"
label_name='org.charter.slice0.p1.run'

if [[ ! "${run_id}" =~ ^charter-p1-[a-z0-9-]{8,80}$ ]]; then
	exit 1
fi

remove_container() {
	local name="$1"
	local label

	if [[ "${name}" == '-' ]]; then
		return
	fi

	if [[ "${name}" != "${run_id}"-* ]]; then
		exit 1
	fi

	if ! docker container inspect "${name}" >/dev/null 2>&1; then
		return
	fi

	label="$(docker container inspect --format "{{ index .Config.Labels \"${label_name}\" }}" "${name}" 2>/dev/null || true)"
	if [[ "${label}" != "${run_id}" ]]; then
		exit 1
	fi

	docker container rm --force "${name}" >/dev/null
}

remove_network() {
	local name="$1"
	local label

	if [[ "${name}" == '-' ]]; then
		return
	fi

	if [[ "${name}" != "${run_id}"-* ]]; then
		exit 1
	fi

	if ! docker network inspect "${name}" >/dev/null 2>&1; then
		return
	fi

	label="$(docker network inspect --format "{{ index .Labels \"${label_name}\" }}" "${name}" 2>/dev/null || true)"
	if [[ "${label}" != "${run_id}" ]]; then
		exit 1
	fi

	docker network rm "${name}" >/dev/null
}

remove_volume() {
	local name="$1"
	local label

	if [[ "${name}" == '-' ]]; then
		return
	fi

	if [[ "${name}" != "${run_id}"-* ]]; then
		exit 1
	fi

	if ! docker volume inspect "${name}" >/dev/null 2>&1; then
		return
	fi

	label="$(docker volume inspect --format "{{ index .Labels \"${label_name}\" }}" "${name}" 2>/dev/null || true)"
	if [[ "${label}" != "${run_id}" ]]; then
		exit 1
	fi

	docker volume rm "${name}" >/dev/null
}

remove_wordpress_directory() {
	local directory="$1"
	local marker
	local parent_directory
	local temporary_root

	if [[ "${directory}" == '-' ]]; then
		return
	fi

	marker="${directory}/.charter-p1-owner"
	if [[ -L "${directory}" || ! -d "${directory}" || ! -f "${marker}" || -L "${marker}" ]]; then
		exit 1
	fi

	if [[ "$(basename "${directory}")" != charter-p1-wordpress.* ]]; then
		exit 1
	fi

	if [[ "$(<"${marker}")" != "${run_id}" ]]; then
		exit 1
	fi

	parent_directory="$(cd "$(dirname "${directory}")" && pwd -P)"
	temporary_root="$(cd "${TMPDIR:-/tmp}" && pwd -P)"
	if [[ "${parent_directory}" != "${temporary_root}" ]]; then
		exit 1
	fi

	rm -rf -- "${directory}"
}

remove_container "${runtime_container}"
remove_container "${database_container}"
remove_network "${network_name}"
remove_volume "${volume_name}"
remove_wordpress_directory "${wordpress_directory}"
