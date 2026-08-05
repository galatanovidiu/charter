#!/usr/bin/env bash

set -euo pipefail
umask 077

if [[ $# -ne 1 ]] || [[ ! -d "$1" ]]; then
	printf 'P3 TLS generation requires one existing private runtime directory.\n' >&2
	exit 1
fi

cert_dir="$(cd "$1" && pwd -P)"
config_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"

case "${cert_dir}" in
	/tmp/charter-p3-cimd.* | /private/tmp/charter-p3-cimd.*) ;;
	*)
		printf 'P3 TLS generation rejected an unbounded output directory.\n' >&2
		exit 1
		;;
esac

openssl req -x509 -newkey rsa:2048 -nodes -sha256 \
	-keyout "${cert_dir}/ca.key" \
	-out "${cert_dir}/ca.crt" \
	-subj '/CN=Charter P3 Proof CA' \
	-days 1 >/dev/null 2>&1

openssl req -new -newkey rsa:2048 -nodes -sha256 \
	-keyout "${cert_dir}/server.key" \
	-out "${cert_dir}/server.csr" \
	-config "${config_dir}/openssl.cnf" >/dev/null 2>&1

openssl x509 -req -sha256 \
	-in "${cert_dir}/server.csr" \
	-CA "${cert_dir}/ca.crt" \
	-CAkey "${cert_dir}/ca.key" \
	-CAcreateserial \
	-copy_extensions copy \
	-out "${cert_dir}/server.crt" \
	-days 1 >/dev/null 2>&1

chmod 600 "${cert_dir}"/*.key
chmod 644 "${cert_dir}"/*.crt
find "${cert_dir}" -type f \( -name 'ca.key' -o -name '*.csr' -o -name '*.srl' \) -delete
