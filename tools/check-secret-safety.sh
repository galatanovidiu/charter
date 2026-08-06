#!/usr/bin/env bash

set -euo pipefail

project_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
archive_path="${project_root}/build/charter.zip"
temporary_directory="$(mktemp -d "${TMPDIR:-/tmp}/charter-secret-safety.XXXXXX")"
secret_pattern='-----BEGIN ([A-Z0-9 ]+ )?PRIVATE KEY-----|A(KIA|SIA)[A-Z0-9]{16}|gh[pousr]_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{30,}|xox[baprs]-[A-Za-z0-9-]{20,}|sk_live_[A-Za-z0-9]{20,}|AIza[A-Za-z0-9_-]{30,}|(cha|chf|chc|chs|chd)_[A-Za-z0-9_-]{40,}'
matched_files=()

cleanup() {
	local exit_code=$?

	if [[ "${temporary_directory}" == */charter-secret-safety.* ]]; then
		find "${temporary_directory}" -type f -delete
		find "${temporary_directory}" -depth -type d -exec rmdir {} \; 2>/dev/null || true
	fi

	exit "${exit_code}"
}

scan_file() {
	local file=$1
	local grep_status

	if grep -I -E -q -- "${secret_pattern}" "${file}"; then
		matched_files+=("${file}")
	else
		grep_status=$?
		if (( grep_status != 1 )); then
			printf 'Secret scanner could not inspect %s.\n' "${file}" >&2
			return "${grep_status}"
		fi
	fi
}

trap cleanup EXIT INT TERM

cd "${project_root}"
while IFS= read -r -d '' file; do
	if [[ "${file}" == 'tools/check-secret-safety.sh' ]]; then
		continue
	fi
	scan_file "${file}"
done < <(git ls-files --cached --others --exclude-standard -z)

if (( ${#matched_files[@]} > 0 )); then
	printf 'Secret-like content was found in release inputs. Only file names are reported:\n' >&2
	printf ' - %s\n' "${matched_files[@]}" >&2
	exit 1
fi

if [[ ! -f "${archive_path}" ]]; then
	echo 'build/charter.zip does not exist. Build and verify the release artifact before running the secret-safety check.' >&2
	exit 1
fi

unzip -qq "${archive_path}" -d "${temporary_directory}"
while IFS= read -r -d '' file; do
	case "${file}" in
		*.env | *.key | *.pem | *.p12 | *.pfx | */id_rsa | */id_ed25519)
			matched_files+=("${file#"${temporary_directory}"/}")
			continue
			;;
	esac
	scan_file "${file}"
done < <(find "${temporary_directory}" -type f -print0)

if (( ${#matched_files[@]} > 0 )); then
	printf 'Secret-like content was found in the plugin artifact. Only archive paths are reported:\n' >&2
	for file in "${matched_files[@]}"; do
		printf ' - %s\n' "${file#"${temporary_directory}"/}" >&2
	done
	exit 1
fi

echo 'Secret-safety checks passed for release inputs and build/charter.zip.'
