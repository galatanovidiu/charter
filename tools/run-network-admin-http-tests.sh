#!/usr/bin/env bash

set -euo pipefail

charter_network_tmp="$(mktemp -d "${TMPDIR:-/tmp}/charter-network-http.XXXXXX")"
charter_network_site_id=''
charter_network_wp_env=(npx --no-install wp-env)
charter_network_config=.wp-env.slice0.json

cleanup() {
	local exit_code=$?

	trap - EXIT INT TERM

	if [[ -n "${charter_network_site_id}" ]]; then
		"${charter_network_wp_env[@]}" run cli --config="${charter_network_config}" wp site delete "${charter_network_site_id}" --yes >/dev/null 2>&1 || true
	fi

	if (( exit_code != 0 )); then
		npm run test:slice0:multisite:logs || true
	fi

	npm run test:slice0:multisite:destroy >/dev/null 2>&1 || true

	if [[ "${charter_network_tmp}" == */charter-network-http.* ]]; then
		find "${charter_network_tmp}" -type f -delete
		rmdir "${charter_network_tmp}" 2>/dev/null || true
	fi

	exit "${exit_code}"
}

assert_status() {
	local expected=$1
	local actual=$2
	local label=$3

	if [[ "${actual}" != "${expected}" ]]; then
		echo "${label}: expected HTTP ${expected}, received ${actual}" >&2
		exit 1
	fi
}

json_field() {
	local json=$1
	local field=$2

	php -r '
		$data = json_decode( $argv[1], true, 512, JSON_THROW_ON_ERROR );
		$value = $data[ $argv[2] ] ?? null;
		if ( ! is_string( $value ) && ! is_int( $value ) ) {
			exit( 1 );
		}
		echo $value;
	' "${json}" "${field}"
}

form_field() {
	local file=$1
	local action=$2
	local field=$3

	php -r '
		$document = new DOMDocument();
		@$document->loadHTMLFile( $argv[1] );
		foreach ( $document->getElementsByTagName( "form" ) as $form ) {
			if ( ! str_contains( $form->getAttribute( "action" ), $argv[2] ) ) {
				continue;
			}
			foreach ( $form->getElementsByTagName( "input" ) as $input ) {
				if ( $input->getAttribute( "name" ) === $argv[3] ) {
					echo $input->getAttribute( "value" );
					exit;
				}
			}
		}
		exit( 1 );
	' "${file}" "${action}" "${field}"
}

containment_form_field() {
	local file=$1
	local scope=$2
	local mode=$3
	local field=$4

	php -r '
		$document = new DOMDocument();
		@$document->loadHTMLFile( $argv[1] );
		foreach ( $document->getElementsByTagName( "form" ) as $form ) {
			$values = array();
			foreach ( $form->getElementsByTagName( "input" ) as $input ) {
				$values[ $input->getAttribute( "name" ) ] = $input->getAttribute( "value" );
			}
			if ( ( $values["scope"] ?? null ) === $argv[2] && ( $values["mode"] ?? null ) === $argv[3] ) {
				echo $values[ $argv[4] ] ?? "";
				exit;
			}
		}
		exit( 1 );
	' "${file}" "${scope}" "${mode}" "${field}"
}

fixture() {
	local action=$1
	local output

	output="$("${charter_network_wp_env[@]}" run cli \
		--config="${charter_network_config}" \
		--env-cwd=wp-content/plugins/charter \
		env \
		"CHARTER_NETWORK_SITE_ID=${charter_network_site_id}" \
		"CHARTER_NETWORK_FIXTURE_ACTION=${action}" \
		wp eval-file tests/fixtures/network-admin-http/site.php)"
	printf '%s\n' "${output}" | sed -n 's/^CHARTER_NETWORK_RESULT=//p' | tail -1
}

load_page() {
	curl --silent --show-error \
		-b "${charter_network_tmp}/cookies.txt" \
		-o "${charter_network_tmp}/network-page.html" \
		-w '%{http_code}' \
		"http://localhost:8891/wp-admin/network/settings.php?page=charter-oauth-network&site_id=${charter_network_site_id}"
}

post_action() {
	local action=$1
	local nonce=$2
	shift 2

	curl --silent --show-error \
		-b "${charter_network_tmp}/cookies.txt" \
		-D "${charter_network_tmp}/action.headers" \
		-o "${charter_network_tmp}/action.html" \
		-w '%{http_code}' \
		--data-urlencode "site_id=${charter_network_site_id}" \
		--data-urlencode "_wpnonce=${nonce}" \
		"$@" \
		"http://localhost:8891/wp-admin/network/edit.php?action=${action}"
}

trap cleanup EXIT INT TERM

export WORDPRESS_BRANCH="${WORDPRESS_BRANCH:-6.9}"
export WP_ENV_CORE="${WP_ENV_CORE:-$(bash tools/resolve-wordpress-core.sh)}"

npm run test:slice0:multisite:destroy >/dev/null 2>&1 || true
npm run test:slice0:multisite:start
"${charter_network_wp_env[@]}" run cli --config="${charter_network_config}" wp core version
"${charter_network_wp_env[@]}" run cli --config="${charter_network_config}" wp plugin activate charter --network

charter_network_site_output="$("${charter_network_wp_env[@]}" run cli --config="${charter_network_config}" wp site create --slug=charter-network-http --title='Charter Network HTTP' --email=admin@example.com --porcelain)"
charter_network_site_id="$(printf '%s\n' "${charter_network_site_output}" | sed -n -E 's/^([0-9]+)$/\1/p' | tail -1)"
if [[ -z "${charter_network_site_id}" ]]; then
	echo 'The disposable Network Admin HTTP site could not be created.' >&2
	exit 1
fi

charter_network_state="$(fixture map)"
if [[ "$(json_field "${charter_network_state}" state)" != 'available' ]]; then
	echo 'Network activation initialized the selected site OAuth boundary.' >&2
	exit 1
fi

curl --silent --show-error \
	-c "${charter_network_tmp}/cookies.txt" \
	-o "${charter_network_tmp}/login.html" \
	--data-urlencode 'log=admin' \
	--data-urlencode 'pwd=password' \
	--data 'wp-submit=Log In' \
	--data-urlencode 'redirect_to=http://localhost:8891/wp-admin/network/settings.php?page=charter-oauth-network' \
	'http://localhost:8891/wp-login.php'

charter_network_status="$(load_page)"
assert_status 200 "${charter_network_status}" 'Network Admin inspection'
if ! grep -q 'OAuth state: Available' "${charter_network_tmp}/network-page.html" || ! grep -q 'does not create network clients, grants, credentials, or an OAuth issuer' "${charter_network_tmp}/network-page.html"; then
	echo 'The Network Admin page did not render the selected Available site boundary.' >&2
	exit 1
fi

charter_network_prepare_action='charter_oauth_network_prepare_site'
charter_network_nonce="$(form_field "${charter_network_tmp}/network-page.html" "${charter_network_prepare_action}" _wpnonce)"
charter_network_status="$(post_action "${charter_network_prepare_action}" "${charter_network_nonce}")"
assert_status 400 "${charter_network_status}" 'unconfirmed selected-site preparation'
charter_network_state="$(fixture status)"
if [[ "$(json_field "${charter_network_state}" state)" != 'available' ]]; then
	echo 'Unconfirmed preparation changed the selected site.' >&2
	exit 1
fi

charter_network_status="$(post_action "${charter_network_prepare_action}" "${charter_network_nonce}" --data 'confirm_action=1')"
assert_status 302 "${charter_network_status}" 'confirmed selected-site preparation'
charter_network_status="$(load_page)"
assert_status 200 "${charter_network_status}" 'Prepared site inspection'
charter_network_issuer="$(form_field "${charter_network_tmp}/network-page.html" charter_oauth_network_enable_site issuer)"
if [[ "${charter_network_issuer}" != 'http://127.0.0.1:8891' ]] || ! grep -q 'OAuth state: Prepared' "${charter_network_tmp}/network-page.html"; then
	echo 'Preparation did not persist the selected site exact issuer.' >&2
	exit 1
fi

curl --fail --location --max-redirs 3 --silent --show-error "${charter_network_issuer}/.well-known/oauth-authorization-server" -o "${charter_network_tmp}/prepared-authorization.json"
curl --fail --location --max-redirs 3 --silent --show-error "${charter_network_issuer}/.well-known/oauth-protected-resource" -o "${charter_network_tmp}/prepared-resource.json"
if [[ "$(json_field "$(<"${charter_network_tmp}/prepared-authorization.json")" issuer)" != "${charter_network_issuer}" ]] \
	|| [[ "$(json_field "$(<"${charter_network_tmp}/prepared-resource.json")" resource)" != "${charter_network_issuer}" ]] \
	|| grep -q 'authorization_endpoint\|authorization_servers' "${charter_network_tmp}/prepared-"*.json; then
	echo 'Prepared metadata did not preserve the exact disabled site issuer boundary.' >&2
	exit 1
fi

charter_network_enable_action='charter_oauth_network_enable_site'
charter_network_nonce="$(form_field "${charter_network_tmp}/network-page.html" "${charter_network_enable_action}" _wpnonce)"
charter_network_status="$(post_action "${charter_network_enable_action}" "${charter_network_nonce}" --data-urlencode "issuer=${charter_network_issuer}")"
assert_status 400 "${charter_network_status}" 'unverified selected-site enablement'
charter_network_state="$(fixture status)"
if [[ "$(json_field "${charter_network_state}" state)" != 'prepared' ]]; then
	echo 'Unverified enablement changed the selected site.' >&2
	exit 1
fi

charter_network_status="$(post_action "${charter_network_enable_action}" "${charter_network_nonce}" --data-urlencode "issuer=${charter_network_issuer}" --data 'discovery_verified=1')"
assert_status 302 "${charter_network_status}" 'verified selected-site enablement'
curl --fail --location --max-redirs 3 --silent --show-error "${charter_network_issuer}/.well-known/oauth-authorization-server" -o "${charter_network_tmp}/enabled-authorization.json"
curl --fail --location --max-redirs 3 --silent --show-error "${charter_network_issuer}/.well-known/oauth-protected-resource" -o "${charter_network_tmp}/enabled-resource.json"
if ! grep -q 'authorization_endpoint' "${charter_network_tmp}/enabled-authorization.json" || ! grep -q 'authorization_servers' "${charter_network_tmp}/enabled-resource.json"; then
	echo 'Enabled metadata did not advertise only the selected site OAuth path.' >&2
	exit 1
fi

charter_network_state="$(fixture create_grants)"
if [[ "$(json_field "${charter_network_state}" active_grants)" != '2' ]]; then
	echo 'The selected site grant fixture was not created.' >&2
	exit 1
fi

charter_network_status="$(load_page)"
assert_status 200 "${charter_network_status}" 'selected-site grant inspection'
if ! grep -q 'Containment mode: resumed' "${charter_network_tmp}/network-page.html"; then
	echo 'The Network Admin page did not render resumed containment status.' >&2
	exit 1
fi

charter_network_containment_action='charter_oauth_network_set_containment'
charter_network_nonce="$(containment_form_field "${charter_network_tmp}/network-page.html" site issuance_paused _wpnonce)"
charter_network_status="$(post_action "${charter_network_containment_action}" "${charter_network_nonce}" --data-urlencode "issuer=${charter_network_issuer}" --data 'scope=site' --data 'mode=issuance_paused' --data 'confirm_action=1')"
assert_status 302 "${charter_network_status}" 'selected-site issuance pause'
charter_network_state="$(fixture status)"
if [[ "$(json_field "${charter_network_state}" containment_mode)" != 'issuance_paused' ]] || [[ "$(json_field "${charter_network_state}" active_grants)" != '2' ]]; then
	echo 'Selected-site issuance pause changed grants or did not persist its mode.' >&2
	exit 1
fi

charter_network_status="$(load_page)"
assert_status 200 "${charter_network_status}" 'paused selected-site inspection'
charter_network_nonce="$(containment_form_field "${charter_network_tmp}/network-page.html" site lockdown _wpnonce)"
charter_network_status="$(post_action "${charter_network_containment_action}" "${charter_network_nonce}" --data-urlencode "issuer=${charter_network_issuer}" --data 'scope=site' --data 'mode=lockdown' --data 'confirm_action=1')"
assert_status 302 "${charter_network_status}" 'selected-site lockdown'
charter_network_state="$(fixture status)"
if [[ "$(json_field "${charter_network_state}" containment_mode)" != 'lockdown' ]] || [[ "$(json_field "${charter_network_state}" active_grants)" != '2' ]]; then
	echo 'Selected-site lockdown changed grants or did not persist its mode.' >&2
	exit 1
fi

charter_network_status="$(load_page)"
assert_status 200 "${charter_network_status}" 'locked-down selected-site inspection'
charter_network_nonce="$(containment_form_field "${charter_network_tmp}/network-page.html" site resumed _wpnonce)"
charter_network_status="$(post_action "${charter_network_containment_action}" "${charter_network_nonce}" --data-urlencode "issuer=${charter_network_issuer}" --data 'scope=site' --data 'mode=resumed' --data 'confirm_action=1')"
assert_status 302 "${charter_network_status}" 'selected-site OAuth resume'
charter_network_state="$(fixture status)"
if [[ "$(json_field "${charter_network_state}" containment_mode)" != 'resumed' ]] || [[ "$(json_field "${charter_network_state}" active_grants)" != '2' ]] || ! grep -q 'network_administrator_issuance_paused' <<<"${charter_network_state}" || ! grep -q 'network_administrator_lockdown' <<<"${charter_network_state}" || ! grep -q 'network_administrator_resumed' <<<"${charter_network_state}"; then
	echo 'Network Admin containment did not preserve state, resume, and record secret-free audit.' >&2
	exit 1
fi

"${charter_network_wp_env[@]}" run cli --config="${charter_network_config}" wp charter oauth containment --network --sites="${charter_network_site_id}" --status > "${charter_network_tmp}/cli-status.txt"
if ! grep -q "Site ${charter_network_site_id}: state=enabled; mode=resumed" "${charter_network_tmp}/cli-status.txt"; then
	echo 'Network-aware WP-CLI did not report the selected issuer containment status.' >&2
	exit 1
fi
"${charter_network_wp_env[@]}" run cli --config="${charter_network_config}" wp charter oauth containment --network --sites="${charter_network_site_id}" --mode=pause --confirm > "${charter_network_tmp}/cli-pause.txt"
if [[ "$(json_field "$(fixture status)" containment_mode)" != 'issuance_paused' ]]; then
	echo 'Selected-network-site WP-CLI pause did not change only the enabled issuer.' >&2
	exit 1
fi
"${charter_network_wp_env[@]}" run cli --config="${charter_network_config}" wp charter oauth containment --network --all --mode=lockdown --confirm > "${charter_network_tmp}/cli-lockdown.txt"
if [[ "$(json_field "$(fixture status)" containment_mode)" != 'lockdown' ]] || ! grep -q 'Site 1: skipped; issuer is not enabled.' "${charter_network_tmp}/cli-lockdown.txt"; then
	echo 'All-site WP-CLI lockdown did not sequentially skip Available sites and change the enabled issuer.' >&2
	exit 1
fi
"${charter_network_wp_env[@]}" run cli --config="${charter_network_config}" wp charter oauth containment --site="${charter_network_site_id}" --mode=resume --confirm > "${charter_network_tmp}/cli-resume.txt"
charter_network_state="$(fixture status)"
if [[ "$(json_field "${charter_network_state}" containment_mode)" != 'resumed' ]] || [[ "$(json_field "${charter_network_state}" active_grants)" != '2' ]] || ! grep -q 'wp_cli_issuance_paused' <<<"${charter_network_state}" || ! grep -q 'wp_cli_lockdown' <<<"${charter_network_state}" || ! grep -q 'wp_cli_resumed' <<<"${charter_network_state}"; then
	echo 'WP-CLI containment did not preserve grants, resume, and record issuer-local audit.' >&2
	exit 1
fi

charter_network_status="$(load_page)"
assert_status 200 "${charter_network_status}" 'resumed selected-site inspection'
charter_network_revoke_action='charter_oauth_network_revoke_site_grant'
charter_network_grant_id="$(form_field "${charter_network_tmp}/network-page.html" "${charter_network_revoke_action}" grant_id)"
charter_network_nonce="$(form_field "${charter_network_tmp}/network-page.html" "${charter_network_revoke_action}" _wpnonce)"
charter_network_status="$(post_action "${charter_network_revoke_action}" "${charter_network_nonce}" --data-urlencode "issuer=${charter_network_issuer}" --data-urlencode "grant_id=${charter_network_grant_id}")"
assert_status 400 "${charter_network_status}" 'unconfirmed selected-site grant revocation'
if [[ "$(json_field "$(fixture status)" active_grants)" != '2' ]]; then
	echo 'Unconfirmed grant revocation changed the selected site.' >&2
	exit 1
fi

charter_network_status="$(post_action "${charter_network_revoke_action}" "${charter_network_nonce}" --data-urlencode "issuer=${charter_network_issuer}" --data-urlencode "grant_id=${charter_network_grant_id}" --data 'confirm_action=1')"
assert_status 302 "${charter_network_status}" 'confirmed selected-site grant revocation'
charter_network_status="$(load_page)"
assert_status 200 "${charter_network_status}" 'post-revocation site inspection'

charter_network_revoke_all_action='charter_oauth_network_revoke_all_site_grants'
charter_network_nonce="$(form_field "${charter_network_tmp}/network-page.html" "${charter_network_revoke_all_action}" _wpnonce)"
charter_network_status="$(post_action "${charter_network_revoke_all_action}" "${charter_network_nonce}" --data-urlencode "issuer=${charter_network_issuer}")"
assert_status 400 "${charter_network_status}" 'unconfirmed selected-site broad revocation'
if [[ "$(json_field "$(fixture status)" active_grants)" != '1' ]]; then
	echo 'Unconfirmed broad revocation changed the selected site.' >&2
	exit 1
fi

charter_network_status="$(post_action "${charter_network_revoke_all_action}" "${charter_network_nonce}" --data-urlencode "issuer=${charter_network_issuer}" --data 'confirm_action=1')"
assert_status 302 "${charter_network_status}" 'confirmed selected-site broad revocation'
charter_network_state="$(fixture status)"
if [[ "$(json_field "${charter_network_state}" active_grants)" != '0' ]] \
	|| ! grep -q 'network_administrator_grant_revocation' <<<"${charter_network_state}" \
	|| ! grep -q 'network_administrator_site_revocation' <<<"${charter_network_state}"; then
	echo 'Network Admin revocation did not close and audit only the selected site grants.' >&2
	exit 1
fi

printf 'Network Admin HTTP control-plane checks passed for one isolated site issuer.\n'
