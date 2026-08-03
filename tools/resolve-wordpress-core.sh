#!/usr/bin/env bash

set -euo pipefail

wordpress_branch="${WORDPRESS_BRANCH:-6.9}"
php_version="${WORDPRESS_PHP_VERSION:-8.4}"
locale="${WORDPRESS_LOCALE:-en_US}"

if [[ ! "${wordpress_branch}" =~ ^[0-9]+\.[0-9]+$ ]]; then
	echo "WORDPRESS_BRANCH must be a major.minor WordPress version." >&2
	exit 1
fi

download_url="$(
	curl --fail --silent --show-error --get \
		--data-urlencode "version=${wordpress_branch}" \
		--data-urlencode "php=${php_version}" \
		--data-urlencode "locale=${locale}" \
		'https://api.wordpress.org/core/version-check/1.7/' |
		jq --raw-output \
			--arg branch "${wordpress_branch}" '
				.offers
				| map(
					select(
						.version
						| test(
							"^"
							+ ($branch | gsub("\\."; "\\."))
							+ "\\.[0-9]+$"
						)
					)
				)
				| max_by(.version | split(".") | map(tonumber))
				| .download
			'
)"

if [[ -z "${download_url}" || "${download_url}" == "null" ]]; then
	echo "Could not resolve the latest WordPress ${wordpress_branch} patch." >&2
	exit 1
fi

printf '%s\n' "${download_url}"
