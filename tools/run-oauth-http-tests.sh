#!/usr/bin/env bash

set -euo pipefail

charter_http_tmp="$(mktemp -d "${TMPDIR:-/tmp}/charter-oauth-http.XXXXXX")"
charter_wp_env=(npx --no-install wp-env)
charter_http_invalid_token="cha_$(printf 'x%.0s' {1..48})"

cleanup() {
	local exit_code=$?

	if (( exit_code != 0 )); then
		npm run test:integration:logs || true
	fi

	npm run test:integration:stop || true

	if [[ "${charter_http_tmp}" == */charter-oauth-http.* ]]; then
		rm -rf -- "${charter_http_tmp}"
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
	local file=$1
	local field=$2

	php -r '
		$data = json_decode( file_get_contents( $argv[1] ), true, 512, JSON_THROW_ON_ERROR );
		$value = $data[ $argv[2] ] ?? null;
		if ( ! is_string( $value ) && ! is_int( $value ) ) {
			exit( 1 );
		}
		echo $value;
	' "${file}" "${field}"
}

html_field() {
	local file=$1
	local field=$2

	php -r '
		$document = new DOMDocument();
		@$document->loadHTMLFile( $argv[1] );
		foreach ( $document->getElementsByTagName( "input" ) as $input ) {
			if ( $input->getAttribute( "name" ) === $argv[2] ) {
				echo $input->getAttribute( "value" );
				exit;
			}
		}
		exit( 1 );
	' "${file}" "${field}"
}

form_field_by_value() {
	local file=$1
	local selector_name=$2
	local selector_value=$3
	local field=$4

	php -r '
		$document = new DOMDocument();
		@$document->loadHTMLFile( $argv[1] );
		foreach ( $document->getElementsByTagName( "form" ) as $form ) {
			$values = array();
			foreach ( $form->getElementsByTagName( "input" ) as $input ) {
				$values[ $input->getAttribute( "name" ) ] = $input->getAttribute( "value" );
			}
			if ( ( $values[ $argv[2] ] ?? null ) === $argv[3] ) {
				echo $values[ $argv[4] ] ?? "";
				exit;
			}
		}
		exit( 1 );
	' "${file}" "${selector_name}" "${selector_value}" "${field}"
}

header_location() {
	local file=$1

	awk 'tolower($1) == "location:" { $1=""; sub(/^ /, ""); sub(/\r$/, ""); print; exit }' "${file}"
}

authorize_logged_in() {
	local client_id=$1
	local redirect_uri=$2
	local scope=$3
	local state=$4
	local verifier=$5
	local prefix=$6
	local resource=${7:-${charter_http_issuer}}
	local authorization_url
	local status
	local transaction
	local nonce
	local callback

	authorization_url="$(php -r '
		$challenge = rtrim( strtr( base64_encode( hash( "sha256", $argv[1], true ) ), "+/", "-_" ), "=" );
		$query = http_build_query(
			array(
				"response_type" => "code",
				"client_id" => $argv[2],
				"redirect_uri" => $argv[3],
				"code_challenge" => $challenge,
				"code_challenge_method" => "S256",
				"resource" => $argv[4],
				"scope" => $argv[5],
				"state" => $argv[6],
			),
			"",
			"&",
			PHP_QUERY_RFC3986
		);
		echo $argv[7] . "&" . $query;
	' "${verifier}" "${client_id}" "${redirect_uri}" "${resource}" "${scope}" "${state}" "${charter_http_authorization_endpoint}")"

	status="$(curl --silent --show-error \
		-b "${charter_http_tmp}/cookies.txt" \
		-D "${charter_http_tmp}/${prefix}-initial.headers" \
		-o "${charter_http_tmp}/${prefix}-consent.html" \
		-w '%{http_code}' \
		"${authorization_url}")"
	if [[ "${status}" == 302 ]]; then
		callback="$(header_location "${charter_http_tmp}/${prefix}-initial.headers")"
		charter_http_authorized_code="$(php -r '
			parse_str( (string) parse_url( $argv[1], PHP_URL_QUERY ), $parameters );
			if ( ( $parameters["iss"] ?? null ) !== $argv[2] || ( $parameters["state"] ?? null ) !== $argv[3] ) {
				exit( 1 );
			}
			echo $parameters["code"] ?? "";
		' "${callback}" "${charter_http_issuer}" "${state}")"
		if [[ -z "${charter_http_authorized_code}" ]]; then
			echo "${prefix} reusable authorization response did not contain an issuer-bound code." >&2
			exit 1
		fi
		return
	fi
	assert_status 200 "${status}" "${prefix} OAuth consent"

	transaction="$(html_field "${charter_http_tmp}/${prefix}-consent.html" transaction)"
	nonce="$(html_field "${charter_http_tmp}/${prefix}-consent.html" _wpnonce)"
	status="$(curl --silent --show-error \
		-b "${charter_http_tmp}/cookies.txt" \
		-D "${charter_http_tmp}/${prefix}-consent.headers" \
		-o "${charter_http_tmp}/${prefix}-consent-response.html" \
		-w '%{http_code}' \
		--data-urlencode "transaction=${transaction}" \
		--data-urlencode "_wpnonce=${nonce}" \
		--data-urlencode 'decision=approve' \
		"${charter_http_authorization_endpoint}")"
	assert_status 302 "${status}" "${prefix} OAuth approval"

	callback="$(header_location "${charter_http_tmp}/${prefix}-consent.headers")"
	charter_http_authorized_code="$(php -r '
		parse_str( (string) parse_url( $argv[1], PHP_URL_QUERY ), $parameters );
		if ( ( $parameters["iss"] ?? null ) !== $argv[2] || ( $parameters["state"] ?? null ) !== $argv[3] ) {
			exit( 1 );
		}
		echo $parameters["code"] ?? "";
	' "${callback}" "${charter_http_issuer}" "${state}")"
	if [[ -z "${charter_http_authorized_code}" ]]; then
		echo "${prefix} authorization response did not contain an issuer-bound code." >&2
		exit 1
	fi
}

trap cleanup EXIT INT TERM

npm run test:integration:start

"${charter_wp_env[@]}" run cli --config=.wp-env.test.json wp plugin activate charter
"${charter_wp_env[@]}" run cli --config=.wp-env.test.json wp rewrite structure '/%postname%/' --hard
"${charter_wp_env[@]}" run cli --config=.wp-env.test.json --env-cwd=wp-content/plugins/charter wp eval-file tests/fixtures/oauth-first-path/reset.php

charter_http_issuer="$("${charter_wp_env[@]}" run cli --config=.wp-env.test.json wp option get home | sed -n -E 's#^(https?://[^[:space:]]+)$#\1#p' | tail -1)"
if [[ -z "${charter_http_issuer}" ]]; then
	echo 'Could not resolve the focused HTTP issuer.' >&2
	exit 1
fi

curl --fail --silent --show-error \
	-H 'Origin: https://client.example.test' \
	-D "${charter_http_tmp}/authorization-metadata.headers" \
	"${charter_http_issuer}/.well-known/oauth-authorization-server" \
	-o "${charter_http_tmp}/authorization-metadata.json"
curl --fail --silent --show-error \
	-H 'Origin: https://client.example.test' \
	"${charter_http_issuer}/.well-known/oauth-protected-resource" \
	-o "${charter_http_tmp}/resource-metadata.json"

if [[ "$(json_field "${charter_http_tmp}/authorization-metadata.json" issuer)" != "${charter_http_issuer}" ]]; then
	echo 'RFC 8414 issuer does not exactly match the canonical origin.' >&2
	exit 1
fi
if [[ "$(json_field "${charter_http_tmp}/resource-metadata.json" resource)" != "${charter_http_issuer}" ]]; then
	echo 'RFC 9728 resource does not exactly match the canonical origin.' >&2
	exit 1
fi
if grep -q '"authorization_endpoint"' "${charter_http_tmp}/authorization-metadata.json" || grep -q '"authorization_servers"' "${charter_http_tmp}/resource-metadata.json"; then
	echo 'Prepared discovery advertised disabled OAuth operations.' >&2
	exit 1
fi
if ! grep -qi '^Access-Control-Allow-Origin: \*' "${charter_http_tmp}/authorization-metadata.headers" || grep -qi '^Access-Control-Allow-Credentials:' "${charter_http_tmp}/authorization-metadata.headers"; then
	echo 'Prepared metadata did not use wildcard non-credentialed CORS.' >&2
	exit 1
fi

"${charter_wp_env[@]}" run cli --config=.wp-env.test.json --env-cwd=wp-content/plugins/charter wp eval-file tests/fixtures/oauth-first-path/setup.php

charter_http_secret_output="$("${charter_wp_env[@]}" run cli --config=.wp-env.test.json --env-cwd=wp-content/plugins/charter wp eval-file tests/fixtures/oauth-first-path/register-confidential.php)"
charter_http_confidential_secret="$(printf '%s\n' "${charter_http_secret_output}" | grep -Eo 'chs_[A-Za-z0-9_-]{43}' | tail -1)"
unset charter_http_secret_output
if [[ -z "${charter_http_confidential_secret}" ]]; then
	echo 'Could not capture the focused backend client secret.' >&2
	exit 1
fi
charter_http_secret_file="${charter_http_tmp}/backend-client-secret"
( umask 077 && printf '%s' "${charter_http_confidential_secret}" > "${charter_http_secret_file}" )
unset charter_http_confidential_secret

curl --fail --silent --show-error \
	-H 'Origin: https://client.example.test' \
	-D "${charter_http_tmp}/authorization-metadata.headers" \
	"${charter_http_issuer}/.well-known/oauth-authorization-server" \
	-o "${charter_http_tmp}/authorization-metadata.json"
curl --fail --silent --show-error \
	-H 'Origin: https://client.example.test' \
	"${charter_http_issuer}/.well-known/oauth-protected-resource" \
	-o "${charter_http_tmp}/resource-metadata.json"
if ! grep -q '"authorization_endpoint"' "${charter_http_tmp}/authorization-metadata.json" || ! grep -q '"authorization_servers"' "${charter_http_tmp}/resource-metadata.json"; then
	echo 'Enabled discovery did not advertise the operational OAuth path.' >&2
	exit 1
fi
if ! grep -qi '^Access-Control-Allow-Origin: \*' "${charter_http_tmp}/authorization-metadata.headers" || grep -qi '^Access-Control-Allow-Credentials:' "${charter_http_tmp}/authorization-metadata.headers"; then
	echo 'Enabled metadata did not use wildcard non-credentialed CORS.' >&2
	exit 1
fi

charter_http_authorization_endpoint="$(json_field "${charter_http_tmp}/authorization-metadata.json" authorization_endpoint)"
charter_http_token_endpoint="$(json_field "${charter_http_tmp}/authorization-metadata.json" token_endpoint)"
charter_http_revocation_endpoint="$(json_field "${charter_http_tmp}/authorization-metadata.json" revocation_endpoint)"
charter_http_registration_endpoint="$(json_field "${charter_http_tmp}/authorization-metadata.json" registration_endpoint)"
charter_http_verifier='0123456789abcdefghijklmnopqrstuvwxyzABCDEFG'
export CHARTER_HTTP_AUTHORIZATION_ENDPOINT="${charter_http_authorization_endpoint}"
export CHARTER_HTTP_ISSUER="${charter_http_issuer}"
export CHARTER_HTTP_VERIFIER="${charter_http_verifier}"

charter_http_authorization_url="$(php -r '
	$challenge = rtrim( strtr( base64_encode( hash( "sha256", getenv( "CHARTER_HTTP_VERIFIER" ), true ) ), "+/", "-_" ), "=" );
	$query = http_build_query(
		array(
			"response_type" => "code",
			"client_id" => "charter-http-client",
			"redirect_uri" => "https://client.example.test/callback",
			"code_challenge" => $challenge,
			"code_challenge_method" => "S256",
			"resource" => getenv( "CHARTER_HTTP_ISSUER" ),
			"scope" => "wordpress:access",
			"state" => "http-client-state",
		),
		"",
		"&",
		PHP_QUERY_RFC3986
	);
	echo getenv( "CHARTER_HTTP_AUTHORIZATION_ENDPOINT" ) . "&" . $query;
')"

charter_http_invalid_redirect_url="${charter_http_authorization_url/https%3A%2F%2Fclient.example.test%2Fcallback/https%3A%2F%2Fevil.example.test%2Fcallback}"
charter_http_status="$(curl --silent --show-error -o "${charter_http_tmp}/invalid-redirect.html" -w '%{http_code}' "${charter_http_invalid_redirect_url}")"
assert_status 400 "${charter_http_status}" 'invalid redirect rejection'

charter_http_status="$(curl --silent --show-error -o "${charter_http_tmp}/duplicate-authorization.html" -w '%{http_code}' "${charter_http_authorization_url}&client_id=duplicate-client")"
assert_status 400 "${charter_http_status}" 'duplicate authorization parameter rejection'

charter_http_status="$(curl --silent --show-error -D "${charter_http_tmp}/logged-out.headers" -o /dev/null -w '%{http_code}' "${charter_http_authorization_url}")"
assert_status 302 "${charter_http_status}" 'WordPress login redirect'
if ! grep -qi '^Location: .*wp-login\.php' "${charter_http_tmp}/logged-out.headers"; then
	echo 'Authorization did not redirect the logged-out user to WordPress login.' >&2
	exit 1
fi

curl --silent --show-error -c "${charter_http_tmp}/cookies.txt" "${charter_http_issuer}/wp-login.php" -o "${charter_http_tmp}/login.html"
charter_http_status="$(curl --silent --show-error \
	-b "${charter_http_tmp}/cookies.txt" \
	-c "${charter_http_tmp}/cookies.txt" \
	-D "${charter_http_tmp}/login.headers" \
	-o /dev/null \
	-w '%{http_code}' \
	--data-urlencode 'log=charter-oauth-user' \
	--data-urlencode 'pwd=charter-http-password' \
	--data-urlencode "redirect_to=${charter_http_authorization_url}" \
	--data-urlencode 'testcookie=1' \
	"${charter_http_issuer}/wp-login.php")"
assert_status 302 "${charter_http_status}" 'WordPress login'

charter_http_status="$(curl --silent --show-error \
	-b "${charter_http_tmp}/cookies.txt" \
	-D "${charter_http_tmp}/consent-page.headers" \
	-o "${charter_http_tmp}/consent.html" \
	-w '%{http_code}' \
	"${charter_http_authorization_url}")"
assert_status 200 "${charter_http_status}" 'OAuth consent'

if ! grep -q 'data-charter-oauth-consent' "${charter_http_tmp}/consent.html" \
	|| ! grep -q 'data-charter-oauth-status' "${charter_http_tmp}/consent.html" \
	|| ! grep -q '/assets/js/oauth-consent.js' "${charter_http_tmp}/consent.html"; then
	echo 'OAuth consent did not include the one-submit progress behavior.' >&2
	exit 1
fi

charter_http_script_nonce="$(php -r '
	$document = new DOMDocument();
	@$document->loadHTMLFile( $argv[1] );
	foreach ( $document->getElementsByTagName( "script" ) as $script ) {
		if ( str_contains( $script->getAttribute( "src" ), "/assets/js/oauth-consent.js" ) ) {
			echo $script->getAttribute( "nonce" );
			exit;
		}
	}
	exit( 1 );
' "${charter_http_tmp}/consent.html")"
if [[ -z "${charter_http_script_nonce}" ]] \
	|| ! grep -Fqi "script-src 'nonce-${charter_http_script_nonce}'" "${charter_http_tmp}/consent-page.headers"; then
	echo 'OAuth consent did not authorize its interaction script with a matching CSP nonce.' >&2
	exit 1
fi
unset charter_http_script_nonce
if ! grep -Fqi "form-action 'self' https://client.example.test;" "${charter_http_tmp}/consent-page.headers"; then
	echo 'OAuth consent did not authorize its exact validated callback origin in form-action.' >&2
	exit 1
fi

charter_http_loopback_url="${charter_http_authorization_url/charter-http-client/charter-http-loopback-client}"
charter_http_loopback_url="${charter_http_loopback_url/https%3A%2F%2Fclient.example.test%2Fcallback/http%3A%2F%2Flocalhost%3A3118%2Fcallback}"
charter_http_status="$(curl --silent --show-error \
	-b "${charter_http_tmp}/cookies.txt" \
	-D "${charter_http_tmp}/loopback-consent.headers" \
	-o "${charter_http_tmp}/loopback-consent.html" \
	-w '%{http_code}' \
	"${charter_http_loopback_url}")"
assert_status 200 "${charter_http_status}" 'loopback OAuth consent'
if ! grep -Fqi "form-action 'self' http://localhost:3118;" "${charter_http_tmp}/loopback-consent.headers"; then
	echo 'Loopback OAuth consent did not authorize its exact runtime callback origin in form-action.' >&2
	exit 1
fi

charter_http_transaction="$(html_field "${charter_http_tmp}/consent.html" transaction)"
charter_http_nonce="$(html_field "${charter_http_tmp}/consent.html" _wpnonce)"
charter_http_status="$(curl --silent --show-error \
	-b "${charter_http_tmp}/cookies.txt" \
	-D "${charter_http_tmp}/consent.headers" \
	-o "${charter_http_tmp}/consent-response.html" \
	-w '%{http_code}' \
	--data-urlencode "transaction=${charter_http_transaction}" \
	--data-urlencode "_wpnonce=${charter_http_nonce}" \
	--data-urlencode 'decision=approve' \
	"${charter_http_authorization_endpoint}")"
assert_status 302 "${charter_http_status}" 'OAuth approval'

charter_http_callback="$(header_location "${charter_http_tmp}/consent.headers")"
export CHARTER_HTTP_CALLBACK="${charter_http_callback}"
charter_http_code="$(php -r '
	parse_str( (string) parse_url( getenv( "CHARTER_HTTP_CALLBACK" ), PHP_URL_QUERY ), $parameters );
	if ( ( $parameters["iss"] ?? null ) !== getenv( "CHARTER_HTTP_ISSUER" ) || ( $parameters["state"] ?? null ) !== "http-client-state" ) {
		exit( 1 );
	}
	echo $parameters["code"] ?? "";
')"
if [[ -z "${charter_http_code}" ]]; then
	echo 'Authorization response did not contain an issuer-bound code.' >&2
	exit 1
fi

charter_http_status="$(curl --silent --show-error \
	-o "${charter_http_tmp}/wrong-pkce.json" \
	-w '%{http_code}' \
	--data-urlencode 'grant_type=authorization_code' \
	--data-urlencode 'client_id=charter-http-client' \
	--data-urlencode "code=${charter_http_code}" \
	--data-urlencode 'code_verifier=zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz' \
	--data-urlencode 'redirect_uri=https://client.example.test/callback' \
	--data-urlencode "resource=${charter_http_issuer}" \
	"${charter_http_token_endpoint}")"
assert_status 400 "${charter_http_status}" 'invalid PKCE rejection'
if [[ "$(json_field "${charter_http_tmp}/wrong-pkce.json" error)" != 'invalid_grant' ]]; then
	echo 'Invalid PKCE did not return invalid_grant.' >&2
	exit 1
fi

charter_http_status="$(curl --silent --show-error \
	-H 'Origin: https://client.example.test' \
	-D "${charter_http_tmp}/token.headers" \
	-o "${charter_http_tmp}/token.json" \
	-w '%{http_code}' \
	--data-urlencode 'grant_type=authorization_code' \
	--data-urlencode 'client_id=charter-http-client' \
	--data-urlencode "code=${charter_http_code}" \
	--data-urlencode "code_verifier=${charter_http_verifier}" \
	--data-urlencode 'redirect_uri=https://client.example.test/callback' \
	--data-urlencode "resource=${charter_http_issuer}" \
	"${charter_http_token_endpoint}")"
assert_status 200 "${charter_http_status}" 'authorization code exchange'
if grep -qi '^Access-Control-Allow-' "${charter_http_tmp}/token.headers"; then
	echo 'The token endpoint exposed an unsupported browser CORS contract.' >&2
	exit 1
fi

charter_http_access_token="$(json_field "${charter_http_tmp}/token.json" access_token)"
charter_http_status="$(curl --silent --show-error \
	-H "Authorization: Bearer ${charter_http_access_token}" \
	-D "${charter_http_tmp}/protected.headers" \
	-o "${charter_http_tmp}/protected.json" \
	-w '%{http_code}' \
	"${charter_http_issuer}/wp-json/charter-http/v1/protected")"
assert_status 200 "${charter_http_status}" 'Bearer-protected REST request'
if ! grep -qi '^Allow: GET' "${charter_http_tmp}/protected.headers"; then
	echo 'The served protected response did not preserve its exact allowed method.' >&2
	exit 1
fi
if [[ "$(json_field "${charter_http_tmp}/protected.json" client_id)" != 'charter-http-client' ]]; then
	echo 'Protected REST route did not receive the exact OAuth client context.' >&2
	exit 1
fi
if [[ "$(json_field "${charter_http_tmp}/protected.json" resource)" != "${charter_http_issuer}" ]]; then
	echo 'Protected REST route did not receive the exact resource context.' >&2
	exit 1
fi

charter_http_status="$(curl --silent --show-error \
	-o "${charter_http_tmp}/replay.json" \
	-w '%{http_code}' \
	--data-urlencode 'grant_type=authorization_code' \
	--data-urlencode 'client_id=charter-http-client' \
	--data-urlencode "code=${charter_http_code}" \
	--data-urlencode "code_verifier=${charter_http_verifier}" \
	"${charter_http_token_endpoint}")"
assert_status 400 "${charter_http_status}" 'authorization code replay rejection'

charter_http_status="$(curl --silent --show-error \
	-H "Authorization: Bearer ${charter_http_access_token}" \
	-o "${charter_http_tmp}/replayed-code-access.json" \
	-w '%{http_code}' \
	"${charter_http_issuer}/wp-json/charter-http/v1/protected")"
assert_status 401 "${charter_http_status}" 'authorization code replay grant closure'

charter_http_status="$(curl --silent --show-error \
	-H "Authorization: Bearer ${charter_http_invalid_token}" \
	-D "${charter_http_tmp}/invalid-bearer.headers" \
	-o "${charter_http_tmp}/invalid-bearer.json" \
	-w '%{http_code}' \
	"${charter_http_issuer}/wp-json/charter-http/v1/protected")"
assert_status 401 "${charter_http_status}" 'invalid Bearer rejection'
if grep -qi 'resource_metadata' "${charter_http_tmp}/invalid-bearer.headers"; then
	echo 'A protected path challenge incorrectly advertised broader origin metadata.' >&2
	exit 1
fi

charter_http_status="$(curl --silent --show-error \
	-H "Authorization: Bearer ${charter_http_invalid_token}" \
	-H 'Origin: https://client.example.test' \
	-D "${charter_http_tmp}/public.headers" \
	-o "${charter_http_tmp}/public.json" \
	-w '%{http_code}' \
	"${charter_http_issuer}/wp-json/charter-http/v1/public")"
assert_status 200 "${charter_http_status}" 'public route preservation'
if ! grep -qi '^Access-Control-Allow-Origin: https://client.example.test' "${charter_http_tmp}/public.headers"; then
	echo 'Charter changed Core CORS behavior on an ordinary public REST route.' >&2
	exit 1
fi

charter_http_status="$(curl --silent --show-error \
	-H 'Content-Type: application/json' \
	-H 'Origin: https://dynamic.example.test' \
	-D "${charter_http_tmp}/dynamic-registration.headers" \
	-o "${charter_http_tmp}/dynamic-registration.json" \
	-w '%{http_code}' \
	--data '{"client_name":"Dynamic HTTP client","redirect_uris":["https://dynamic.example.test/callback"],"token_endpoint_auth_method":"none","grant_types":["authorization_code","refresh_token"],"response_types":["code"]}' \
	"${charter_http_registration_endpoint}")"
assert_status 201 "${charter_http_status}" 'dynamic client registration'
if grep -qi '^Access-Control-Allow-' "${charter_http_tmp}/dynamic-registration.headers"; then
	echo 'The registration endpoint exposed an unsupported browser CORS contract.' >&2
	exit 1
fi
if ! grep -qi '^Cache-Control: .*no-store' "${charter_http_tmp}/dynamic-registration.headers"; then
	echo 'The registration endpoint response was not marked no-store.' >&2
	exit 1
fi
if grep -q '"client_secret"' "${charter_http_tmp}/dynamic-registration.json"; then
	echo 'A public dynamic registration unexpectedly received a client secret.' >&2
	exit 1
fi
charter_http_dynamic_client="$(json_field "${charter_http_tmp}/dynamic-registration.json" client_id)"

charter_http_dynamic_verifier='mnopqrstuvwxyzABCDEFG0123456789abcdefghijklm'
authorize_logged_in \
	"${charter_http_dynamic_client}" \
	'https://dynamic.example.test/callback' \
	'wordpress:access offline_access' \
	'dynamic-client-state' \
	"${charter_http_dynamic_verifier}" \
	'dynamic-client'
charter_http_status="$(curl --silent --show-error \
	-o "${charter_http_tmp}/dynamic-token.json" \
	-w '%{http_code}' \
	--data-urlencode 'grant_type=authorization_code' \
	--data-urlencode "client_id=${charter_http_dynamic_client}" \
	--data-urlencode "code=${charter_http_authorized_code}" \
	--data-urlencode "code_verifier=${charter_http_dynamic_verifier}" \
	--data-urlencode 'redirect_uri=https://dynamic.example.test/callback' \
	"${charter_http_token_endpoint}")"
assert_status 200 "${charter_http_status}" 'dynamic client authorization code exchange'
charter_http_dynamic_access="$(json_field "${charter_http_tmp}/dynamic-token.json" access_token)"
charter_http_dynamic_refresh="$(json_field "${charter_http_tmp}/dynamic-token.json" refresh_token)"
charter_http_status="$(curl --silent --show-error \
	-H "Authorization: Bearer ${charter_http_dynamic_access}" \
	-o "${charter_http_tmp}/dynamic-protected.json" \
	-w '%{http_code}' \
	"${charter_http_issuer}/wp-json/charter-http/v1/protected")"
assert_status 200 "${charter_http_status}" 'dynamic client Bearer-protected REST request'
if [[ "$(json_field "${charter_http_tmp}/dynamic-protected.json" client_id)" != "${charter_http_dynamic_client}" ]]; then
	echo 'The dynamic client context was not preserved through the protected route.' >&2
	exit 1
fi

charter_http_backend_verifier='ABCDEFGabcdefghijklmnopqrstuvwxyz0123456789'
authorize_logged_in \
	'charter-http-backend' \
	'https://backend.example.test/callback' \
	'wordpress:access offline_access' \
	'backend-refresh-state' \
	"${charter_http_backend_verifier}" \
	'backend-refresh'
charter_http_backend_code="${charter_http_authorized_code}"

charter_http_status="$(curl --silent --show-error \
	-o "${charter_http_tmp}/backend-missing-secret.json" \
	-w '%{http_code}' \
	--data-urlencode 'grant_type=authorization_code' \
	--data-urlencode 'client_id=charter-http-backend' \
	--data-urlencode "code=${charter_http_backend_code}" \
	--data-urlencode "code_verifier=${charter_http_backend_verifier}" \
	--data-urlencode 'redirect_uri=https://backend.example.test/callback' \
	"${charter_http_token_endpoint}")"
assert_status 401 "${charter_http_status}" 'confidential exchange without client secret'

charter_http_status="$(curl --silent --show-error \
	-o "${charter_http_tmp}/backend-token.json" \
	-w '%{http_code}' \
	--data-urlencode 'grant_type=authorization_code' \
	--data-urlencode 'client_id=charter-http-backend' \
	--data-urlencode "client_secret@${charter_http_secret_file}" \
	--data-urlencode "code=${charter_http_backend_code}" \
	--data-urlencode "code_verifier=${charter_http_backend_verifier}" \
	--data-urlencode 'redirect_uri=https://backend.example.test/callback' \
	--data-urlencode "resource=${charter_http_issuer}" \
	"${charter_http_token_endpoint}")"
assert_status 200 "${charter_http_status}" 'confidential authorization code exchange'
charter_http_backend_access="$(json_field "${charter_http_tmp}/backend-token.json" access_token)"
charter_http_backend_refresh="$(json_field "${charter_http_tmp}/backend-token.json" refresh_token)"

curl --silent --show-error \
	-o "${charter_http_tmp}/backend-rotation-one.json" \
	-w '%{http_code}' \
	--data-urlencode 'grant_type=refresh_token' \
	--data-urlencode 'client_id=charter-http-backend' \
	--data-urlencode "client_secret@${charter_http_secret_file}" \
	--data-urlencode "refresh_token=${charter_http_backend_refresh}" \
	--data-urlencode "resource=${charter_http_issuer}" \
	"${charter_http_token_endpoint}" > "${charter_http_tmp}/backend-rotation-one.status" &
charter_http_rotation_one_pid=$!
curl --silent --show-error \
	-o "${charter_http_tmp}/backend-rotation-two.json" \
	-w '%{http_code}' \
	--data-urlencode 'grant_type=refresh_token' \
	--data-urlencode 'client_id=charter-http-backend' \
	--data-urlencode "client_secret@${charter_http_secret_file}" \
	--data-urlencode "refresh_token=${charter_http_backend_refresh}" \
	--data-urlencode "resource=${charter_http_issuer}" \
	"${charter_http_token_endpoint}" > "${charter_http_tmp}/backend-rotation-two.status" &
charter_http_rotation_two_pid=$!
wait "${charter_http_rotation_one_pid}"
wait "${charter_http_rotation_two_pid}"

charter_http_rotation_one_status="$(< "${charter_http_tmp}/backend-rotation-one.status")"
charter_http_rotation_two_status="$(< "${charter_http_tmp}/backend-rotation-two.status")"
if [[ "${charter_http_rotation_one_status}:${charter_http_rotation_two_status}" == '200:400' ]]; then
	charter_http_rotation_winner="${charter_http_tmp}/backend-rotation-one.json"
	charter_http_rotation_loser="${charter_http_tmp}/backend-rotation-two.json"
elif [[ "${charter_http_rotation_one_status}:${charter_http_rotation_two_status}" == '400:200' ]]; then
	charter_http_rotation_winner="${charter_http_tmp}/backend-rotation-two.json"
	charter_http_rotation_loser="${charter_http_tmp}/backend-rotation-one.json"
else
	echo "concurrent refresh: expected one HTTP 200 and one HTTP 400, received ${charter_http_rotation_one_status} and ${charter_http_rotation_two_status}" >&2
	exit 1
fi
if [[ "$(json_field "${charter_http_rotation_loser}" error)" != 'invalid_grant' ]]; then
	echo 'The losing refresh replay did not return invalid_grant.' >&2
	exit 1
fi
charter_http_rotated_access="$(json_field "${charter_http_rotation_winner}" access_token)"
charter_http_status="$(curl --silent --show-error \
	-H "Authorization: Bearer ${charter_http_rotated_access}" \
	-o "${charter_http_tmp}/backend-replay-closed.json" \
	-w '%{http_code}' \
	"${charter_http_issuer}/wp-json/charter-http/v1/protected")"
assert_status 401 "${charter_http_status}" 'refresh replay grant closure'

authorize_logged_in \
	'charter-http-backend' \
	'https://backend.example.test/callback' \
	'wordpress:access offline_access' \
	'backend-revocation-state' \
	"${charter_http_backend_verifier}" \
	'backend-revocation'
charter_http_status="$(curl --silent --show-error \
	-o "${charter_http_tmp}/backend-revocable-token.json" \
	-w '%{http_code}' \
	--data-urlencode 'grant_type=authorization_code' \
	--data-urlencode 'client_id=charter-http-backend' \
	--data-urlencode "client_secret@${charter_http_secret_file}" \
	--data-urlencode "code=${charter_http_authorized_code}" \
	--data-urlencode "code_verifier=${charter_http_backend_verifier}" \
	--data-urlencode 'redirect_uri=https://backend.example.test/callback' \
	"${charter_http_token_endpoint}")"
assert_status 200 "${charter_http_status}" 'revocable confidential grant issue'
charter_http_revocable_access="$(json_field "${charter_http_tmp}/backend-revocable-token.json" access_token)"
charter_http_revocable_refresh="$(json_field "${charter_http_tmp}/backend-revocable-token.json" refresh_token)"

authorize_logged_in \
	"${charter_http_dynamic_client}" \
	'https://dynamic.example.test/callback' \
	'wordpress:access offline_access' \
	'containment-code-state' \
	"${charter_http_dynamic_verifier}" \
	'containment-code'
charter_http_containment_code="${charter_http_authorized_code}"

curl --silent --show-error -c "${charter_http_tmp}/admin-cookies.txt" "${charter_http_issuer}/wp-login.php" -o "${charter_http_tmp}/admin-login.html"
charter_http_status="$(curl --silent --show-error \
	-b "${charter_http_tmp}/admin-cookies.txt" \
	-c "${charter_http_tmp}/admin-cookies.txt" \
	-D "${charter_http_tmp}/admin-login.headers" \
	-o /dev/null \
	-w '%{http_code}' \
	--data-urlencode 'log=charter-oauth-admin' \
	--data-urlencode 'pwd=charter-http-admin-password' \
	--data-urlencode "redirect_to=${charter_http_issuer}/wp-admin/options-general.php?page=charter-oauth" \
	--data-urlencode 'testcookie=1' \
	"${charter_http_issuer}/wp-login.php")"
assert_status 302 "${charter_http_status}" 'WordPress administrator login'

charter_http_status="$(curl --silent --show-error \
	-b "${charter_http_tmp}/admin-cookies.txt" \
	-o "${charter_http_tmp}/settings-containment.html" \
	-w '%{http_code}' \
	"${charter_http_issuer}/wp-admin/options-general.php?page=charter-oauth")"
assert_status 200 "${charter_http_status}" 'Site Admin containment inspection'
if ! grep -q 'Emergency containment' "${charter_http_tmp}/settings-containment.html" || ! grep -q 'Mode: resumed' "${charter_http_tmp}/settings-containment.html"; then
	echo 'Site Admin did not expose the resumed containment state.' >&2
	exit 1
fi
charter_http_nonce="$(form_field_by_value "${charter_http_tmp}/settings-containment.html" mode issuance_paused _wpnonce)"
charter_http_status="$(curl --silent --show-error \
	-b "${charter_http_tmp}/admin-cookies.txt" \
	-D "${charter_http_tmp}/settings-pause.headers" \
	-o /dev/null \
	-w '%{http_code}' \
	--data 'action=charter_oauth_set_emergency_mode' \
	--data 'mode=issuance_paused' \
	--data 'confirm_action=1' \
	--data-urlencode "_wpnonce=${charter_http_nonce}" \
	"${charter_http_issuer}/wp-admin/admin-post.php")"
assert_status 302 "${charter_http_status}" 'Site Admin issuance pause'

charter_http_status="$(curl --silent --show-error \
	-b "${charter_http_tmp}/admin-cookies.txt" \
	-o "${charter_http_tmp}/settings-paused.html" \
	-w '%{http_code}' \
	"${charter_http_issuer}/wp-admin/options-general.php?page=charter-oauth")"
assert_status 200 "${charter_http_status}" 'paused Site Admin containment inspection'
if ! grep -q 'Mode: issuance_paused' "${charter_http_tmp}/settings-paused.html"; then
	echo 'Site Admin did not report the issuer-local paused state.' >&2
	exit 1
fi
charter_http_nonce="$(form_field_by_value "${charter_http_tmp}/settings-paused.html" mode resumed _wpnonce)"
charter_http_status="$(curl --silent --show-error \
	-b "${charter_http_tmp}/admin-cookies.txt" \
	-D "${charter_http_tmp}/settings-resume.headers" \
	-o /dev/null \
	-w '%{http_code}' \
	--data 'action=charter_oauth_set_emergency_mode' \
	--data 'mode=resumed' \
	--data 'confirm_action=1' \
	--data-urlencode "_wpnonce=${charter_http_nonce}" \
	"${charter_http_issuer}/wp-admin/admin-post.php")"
assert_status 302 "${charter_http_status}" 'Site Admin OAuth resume'

"${charter_wp_env[@]}" run cli --config=.wp-env.test.json wp charter oauth containment --status > "${charter_http_tmp}/containment-resumed.txt"
if ! grep -q 'mode=resumed' "${charter_http_tmp}/containment-resumed.txt"; then
	echo 'WP-CLI did not report the default resumed containment mode.' >&2
	exit 1
fi
"${charter_wp_env[@]}" run cli --config=.wp-env.test.json wp charter oauth containment --mode=pause --confirm > "${charter_http_tmp}/containment-pause.txt"

curl --fail --silent --show-error \
	"${charter_http_issuer}/.well-known/oauth-authorization-server" \
	-o "${charter_http_tmp}/paused-authorization-metadata.json"
if grep -q 'registration_endpoint' "${charter_http_tmp}/paused-authorization-metadata.json"; then
	echo 'Paused metadata still advertised Dynamic Client Registration.' >&2
	exit 1
fi

charter_http_status="$(curl --silent --show-error \
	-H 'Content-Type: application/json' \
	-o "${charter_http_tmp}/paused-registration.json" \
	-w '%{http_code}' \
	--data '{"client_name":"Paused client","redirect_uris":["https://paused.example.test/callback"],"token_endpoint_auth_method":"none","grant_types":["authorization_code"],"response_types":["code"]}' \
	"${charter_http_registration_endpoint}")"
assert_status 503 "${charter_http_status}" 'paused Dynamic Client Registration'
if [[ "$(json_field "${charter_http_tmp}/paused-registration.json" error)" != 'temporarily_unavailable' ]]; then
	echo 'Paused Dynamic Client Registration did not own the temporarily_unavailable error.' >&2
	exit 1
fi

charter_http_status="$(curl --silent --show-error \
	-b "${charter_http_tmp}/cookies.txt" \
	-o "${charter_http_tmp}/paused-authorization.html" \
	-w '%{http_code}' \
	"${charter_http_authorization_url}")"
assert_status 503 "${charter_http_status}" 'paused new authorization'

charter_http_status="$(curl --silent --show-error \
	-o "${charter_http_tmp}/paused-code-exchange.json" \
	-w '%{http_code}' \
	--data-urlencode 'grant_type=authorization_code' \
	--data-urlencode "client_id=${charter_http_dynamic_client}" \
	--data-urlencode "code=${charter_http_containment_code}" \
	--data-urlencode "code_verifier=${charter_http_dynamic_verifier}" \
	--data-urlencode 'redirect_uri=https://dynamic.example.test/callback' \
	"${charter_http_token_endpoint}")"
assert_status 503 "${charter_http_status}" 'paused authorization-code exchange'
if [[ "$(json_field "${charter_http_tmp}/paused-code-exchange.json" error)" != 'temporarily_unavailable' ]]; then
	echo 'Paused code exchange did not own the temporarily_unavailable error.' >&2
	exit 1
fi

charter_http_status="$(curl --silent --show-error \
	-o "${charter_http_tmp}/paused-refresh.json" \
	-w '%{http_code}' \
	--data-urlencode 'grant_type=refresh_token' \
	--data-urlencode "client_id=${charter_http_dynamic_client}" \
	--data-urlencode "refresh_token=${charter_http_dynamic_refresh}" \
	"${charter_http_token_endpoint}")"
assert_status 503 "${charter_http_status}" 'paused refresh'
if [[ "$(json_field "${charter_http_tmp}/paused-refresh.json" error)" != 'temporarily_unavailable' ]]; then
	echo 'Paused refresh did not own the temporarily_unavailable error.' >&2
	exit 1
fi

charter_http_status="$(curl --silent --show-error \
	-H "Authorization: Bearer ${charter_http_dynamic_access}" \
	-o "${charter_http_tmp}/paused-existing-access.json" \
	-w '%{http_code}' \
	"${charter_http_issuer}/wp-json/charter-http/v1/protected")"
assert_status 200 "${charter_http_status}" 'paused existing Bearer access'

"${charter_wp_env[@]}" run cli --config=.wp-env.test.json wp charter oauth containment --mode=lockdown --confirm > "${charter_http_tmp}/containment-lockdown.txt"
charter_http_status="$(curl --silent --show-error \
	-H "Authorization: Bearer ${charter_http_dynamic_access}" \
	-o "${charter_http_tmp}/lockdown-existing-access.json" \
	-w '%{http_code}' \
	"${charter_http_issuer}/wp-json/charter-http/v1/protected")"
assert_status 401 "${charter_http_status}" 'lockdown existing Bearer rejection'
if [[ "$(json_field "${charter_http_tmp}/lockdown-existing-access.json" error)" != 'invalid_token' ]]; then
	echo 'Lockdown did not return the generic Charter invalid-token owner.' >&2
	exit 1
fi

charter_http_status="$(curl --silent --show-error \
	-H "Authorization: Bearer ${charter_http_dynamic_access}" \
	-o "${charter_http_tmp}/lockdown-public.json" \
	-w '%{http_code}' \
	"${charter_http_issuer}/wp-json/charter-http/v1/public")"
assert_status 200 "${charter_http_status}" 'lockdown public route preservation'

charter_http_status="$(curl --silent --show-error \
	-H 'Origin: https://backend.example.test' \
	-D "${charter_http_tmp}/revocation.headers" \
	-o "${charter_http_tmp}/revocation.json" \
	-w '%{http_code}' \
	--data-urlencode 'client_id=charter-http-backend' \
	--data-urlencode "client_secret@${charter_http_secret_file}" \
	--data-urlencode "token=${charter_http_revocable_refresh}" \
	--data-urlencode 'token_type_hint=refresh_token' \
	"${charter_http_revocation_endpoint}")"
assert_status 200 "${charter_http_status}" 'RFC 7009 refresh-token revocation'
if grep -qi '^Access-Control-Allow-' "${charter_http_tmp}/revocation.headers"; then
	echo 'The revocation endpoint exposed an unsupported browser CORS contract.' >&2
	exit 1
fi
charter_http_status="$(curl --silent --show-error \
	-H "Authorization: Bearer ${charter_http_revocable_access}" \
	-o "${charter_http_tmp}/revoked-access.json" \
	-w '%{http_code}' \
	"${charter_http_issuer}/wp-json/charter-http/v1/protected")"
assert_status 401 "${charter_http_status}" 'RFC 7009 grant-wide descendant closure'

"${charter_wp_env[@]}" run cli --config=.wp-env.test.json wp charter oauth containment --mode=resume --confirm > "${charter_http_tmp}/containment-resume.txt"
curl --fail --silent --show-error \
	"${charter_http_issuer}/.well-known/oauth-authorization-server" \
	-o "${charter_http_tmp}/resumed-authorization-metadata.json"
if ! grep -q 'registration_endpoint' "${charter_http_tmp}/resumed-authorization-metadata.json"; then
	echo 'Resumed metadata did not restore Dynamic Client Registration advertisement.' >&2
	exit 1
fi

charter_http_status="$(curl --silent --show-error \
	-o "${charter_http_tmp}/resumed-code-exchange.json" \
	-w '%{http_code}' \
	--data-urlencode 'grant_type=authorization_code' \
	--data-urlencode "client_id=${charter_http_dynamic_client}" \
	--data-urlencode "code=${charter_http_containment_code}" \
	--data-urlencode "code_verifier=${charter_http_dynamic_verifier}" \
	--data-urlencode 'redirect_uri=https://dynamic.example.test/callback' \
	"${charter_http_token_endpoint}")"
assert_status 200 "${charter_http_status}" 'resumed authorization-code exchange'

charter_http_mcp_resource="${charter_http_issuer}/wp-json/charter-http/v1/mcp"
charter_http_mcp_metadata="${charter_http_issuer}/.well-known/oauth-protected-resource/wp-json/charter-http/v1/mcp"
charter_http_status="$(curl --silent --show-error \
	-H 'Origin: https://mcp-client.example.test' \
	-D "${charter_http_tmp}/mcp-metadata.headers" \
	-o "${charter_http_tmp}/mcp-metadata.json" \
	-w '%{http_code}' \
	"${charter_http_mcp_metadata}")"
assert_status 200 "${charter_http_status}" 'MCP protected-resource metadata'
if [[ "$(json_field "${charter_http_tmp}/mcp-metadata.json" resource)" != "${charter_http_mcp_resource}" ]]; then
	echo 'MCP protected-resource metadata did not identify the exact path resource.' >&2
	exit 1
fi
if ! grep -q '"scopes_supported":\["charter-http-mcp:access"\]' "${charter_http_tmp}/mcp-metadata.json"; then
	echo 'MCP protected-resource metadata did not publish its exact registered scope.' >&2
	exit 1
fi
if ! grep -qi '^Access-Control-Allow-Origin: \*' "${charter_http_tmp}/mcp-metadata.headers"; then
	echo 'MCP protected-resource metadata did not preserve wildcard discovery CORS.' >&2
	exit 1
fi

charter_http_mcp_verifier='zyxwvutsrqponmlkjihgfedcba9876543210ABCDEFG'
authorize_logged_in \
	'charter-http-mcp-client' \
	'https://mcp-client.example.test/callback' \
	'charter-http-mcp:access offline_access' \
	'mcp-profile-state' \
	"${charter_http_mcp_verifier}" \
	'mcp-profile' \
	"${charter_http_mcp_resource}"
charter_http_mcp_code="${charter_http_authorized_code}"
if ! grep -q 'Charter HTTP MCP access' "${charter_http_tmp}/mcp-profile-consent.html" || ! grep -q 'Use the focused MCP-compatible server as your WordPress account.' "${charter_http_tmp}/mcp-profile-consent.html"; then
	echo 'MCP consent did not present the registered user-facing scope name and description.' >&2
	exit 1
fi

charter_http_status="$(curl --silent --show-error \
	-o "${charter_http_tmp}/mcp-wrong-resource.json" \
	-w '%{http_code}' \
	--data-urlencode 'grant_type=authorization_code' \
	--data-urlencode 'client_id=charter-http-mcp-client' \
	--data-urlencode "code=${charter_http_mcp_code}" \
	--data-urlencode "code_verifier=${charter_http_mcp_verifier}" \
	--data-urlencode 'redirect_uri=https://mcp-client.example.test/callback' \
	--data-urlencode "resource=${charter_http_issuer}" \
	"${charter_http_token_endpoint}")"
assert_status 400 "${charter_http_status}" 'MCP cross-resource code exchange rejection'
if [[ "$(json_field "${charter_http_tmp}/mcp-wrong-resource.json" error)" != 'invalid_target' ]]; then
	echo 'MCP cross-resource exchange did not return invalid_target.' >&2
	exit 1
fi

charter_http_status="$(curl --silent --show-error \
	-o "${charter_http_tmp}/mcp-token.json" \
	-w '%{http_code}' \
	--data-urlencode 'grant_type=authorization_code' \
	--data-urlencode 'client_id=charter-http-mcp-client' \
	--data-urlencode "code=${charter_http_mcp_code}" \
	--data-urlencode "code_verifier=${charter_http_mcp_verifier}" \
	--data-urlencode 'redirect_uri=https://mcp-client.example.test/callback' \
	--data-urlencode "resource=${charter_http_mcp_resource}" \
	"${charter_http_token_endpoint}")"
assert_status 200 "${charter_http_status}" 'MCP authorization code exchange'
if [[ "$(json_field "${charter_http_tmp}/mcp-token.json" resource)" != "${charter_http_mcp_resource}" ]] || [[ "$(json_field "${charter_http_tmp}/mcp-token.json" scope)" != 'charter-http-mcp:access' ]]; then
	echo 'MCP token response did not retain its exact resource and canonical scope.' >&2
	exit 1
fi
charter_http_mcp_access="$(json_field "${charter_http_tmp}/mcp-token.json" access_token)"
charter_http_mcp_refresh="$(json_field "${charter_http_tmp}/mcp-token.json" refresh_token)"

charter_http_status="$(curl --silent --show-error \
	-H "Authorization: Bearer ${charter_http_mcp_access}" \
	-o "${charter_http_tmp}/mcp-protected.json" \
	-w '%{http_code}' \
	"${charter_http_mcp_resource}")"
assert_status 200 "${charter_http_status}" 'MCP Bearer-protected request'
if [[ "$(json_field "${charter_http_tmp}/mcp-protected.json" resource)" != "${charter_http_mcp_resource}" ]]; then
	echo 'MCP route did not receive its exact OAuth resource context.' >&2
	exit 1
fi

charter_http_status="$(curl --silent --show-error \
	-H "Authorization: Bearer ${charter_http_mcp_access}" \
	-o "${charter_http_tmp}/mcp-default-resource.json" \
	-w '%{http_code}' \
	"${charter_http_issuer}/wp-json/charter-http/v1/protected")"
assert_status 401 "${charter_http_status}" 'MCP token default-resource rejection'

charter_http_status="$(curl --silent --show-error \
	-D "${charter_http_tmp}/mcp-challenge.headers" \
	-o "${charter_http_tmp}/mcp-challenge.json" \
	-w '%{http_code}' \
	"${charter_http_mcp_resource}")"
assert_status 401 "${charter_http_status}" 'MCP exact-resource challenge'
if ! grep -Fqi "resource_metadata=\"${charter_http_mcp_metadata}\"" "${charter_http_tmp}/mcp-challenge.headers"; then
	echo 'MCP challenge did not reference exact path-specific protected-resource metadata.' >&2
	exit 1
fi

"${charter_wp_env[@]}" run cli --config=.wp-env.test.json wp option update charter_http_disable_mcp_profile 1
charter_http_status="$(curl --silent --show-error \
	-o "${charter_http_tmp}/mcp-missing-provider-metadata.json" \
	-w '%{http_code}' \
	"${charter_http_mcp_metadata}")"
assert_status 404 "${charter_http_status}" 'missing MCP provider metadata rejection'
curl --fail --silent --show-error \
	"${charter_http_issuer}/.well-known/oauth-authorization-server" \
	-o "${charter_http_tmp}/mcp-missing-provider-authorization-metadata.json"
if grep -q 'charter-http-mcp:access' "${charter_http_tmp}/mcp-missing-provider-authorization-metadata.json"; then
	echo 'Authorization-server metadata retained a scope whose provider stopped registering.' >&2
	exit 1
fi

charter_http_status="$(curl --silent --show-error \
	-H "Authorization: Bearer ${charter_http_mcp_access}" \
	-o "${charter_http_tmp}/mcp-missing-provider-access.json" \
	-w '%{http_code}' \
	"${charter_http_mcp_resource}")"
assert_status 401 "${charter_http_status}" 'missing MCP provider access rejection'

charter_http_status="$(curl --silent --show-error \
	-o "${charter_http_tmp}/mcp-missing-provider-refresh.json" \
	-w '%{http_code}' \
	--data-urlencode 'grant_type=refresh_token' \
	--data-urlencode 'client_id=charter-http-mcp-client' \
	--data-urlencode "refresh_token=${charter_http_mcp_refresh}" \
	--data-urlencode "resource=${charter_http_mcp_resource}" \
	"${charter_http_token_endpoint}")"
assert_status 400 "${charter_http_status}" 'missing MCP provider refresh rejection'
if [[ "$(json_field "${charter_http_tmp}/mcp-missing-provider-refresh.json" error)" != 'invalid_grant' ]]; then
	echo 'A missing MCP scope provider did not fail refresh closed.' >&2
	exit 1
fi

echo 'OAuth lifecycle real-HTTP verification passed.'

trap - EXIT INT TERM
cleanup
