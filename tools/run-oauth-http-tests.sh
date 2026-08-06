#!/usr/bin/env bash

set -euo pipefail

charter_http_tmp="$(mktemp -d "${TMPDIR:-/tmp}/charter-oauth-http.XXXXXX")"
charter_wp_env=(npx --no-install wp-env)

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
	' "${verifier}" "${client_id}" "${redirect_uri}" "${charter_http_issuer}" "${scope}" "${state}" "${charter_http_authorization_endpoint}")"

	status="$(curl --silent --show-error \
		-b "${charter_http_tmp}/cookies.txt" \
		-o "${charter_http_tmp}/${prefix}-consent.html" \
		-w '%{http_code}' \
		"${authorization_url}")"
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
	-o "${charter_http_tmp}/consent.html" \
	-w '%{http_code}' \
	"${charter_http_authorization_url}")"
assert_status 200 "${charter_http_status}" 'OAuth consent'

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
	-H 'Authorization: Bearer cha_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa' \
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
	-H 'Authorization: Bearer cha_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa' \
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

echo 'OAuth lifecycle real-HTTP verification passed.'

trap - EXIT INT TERM
cleanup
