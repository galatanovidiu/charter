#!/usr/bin/env bash

set -euo pipefail
umask 077

# The proof is fully non-interactive. Closing stdin prevents Docker Compose
# exec/run transports from waiting on an attached terminal after the bounded
# child process has exited.
exec </dev/null

project_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
compose_file="${project_root}/tests/fixtures/cimd-outbound-safety/docker-compose.yml"
validator="${project_root}/tools/validate-slice0-cimd-outbound-safety-output.php"
timeout_command="$(command -v gtimeout || command -v timeout || true)"

p3_runtime_dir="$(mktemp -d /tmp/charter-p3-cimd.XXXXXX)"
p3_private_dir="${p3_runtime_dir}/private"
p3_state_dir="${p3_runtime_dir}/state"
p3_cert_dir="${p3_runtime_dir}/certs"
p3_wordpress_root="${p3_runtime_dir}/wordpress"
p3_project_name="charter-p3-$$-${RANDOM}"
p3_compose_started=false
p3_cleanup_complete=false
p3_failure_emitted=false

install -d -m 700 "${p3_private_dir}" "${p3_cert_dir}"
install -d -m 777 "${p3_state_dir}"

export P3_PROJECT_ROOT="${project_root}"
export P3_STATE_DIR="${p3_state_dir}"
export P3_CERT_DIR="${p3_cert_dir}"
export P3_WORDPRESS_ROOT="${p3_wordpress_root}"

emit_record() {
	local status=$1
	local phase=$2
	local case_id=$3
	local runtime=$4
	local error=$5
	local elapsed_ms=${6:-0}
	local containers_remaining=${7:-0}
	local networks_remaining=${8:-0}
	local temp_files_remaining=${9:-0}
	local private_keys_remaining=${10:-0}
	local processes_remaining=${11:-0}
	local listeners_remaining=${12:-0}

	printf '%s\n' "{\"status\":\"${status}\",\"phase\":\"${phase}\",\"case_id\":\"${case_id}\",\"runtime_classification\":\"${runtime}\",\"url_classification\":\"not-applicable\",\"dns_classification\":\"not-applicable\",\"address_classification\":\"not-applicable\",\"media_classification\":\"not-applicable\",\"cache_classification\":\"not-applicable\",\"error_classification\":\"${error}\",\"status_code\":0,\"body_bytes\":0,\"elapsed_ms\":${elapsed_ms},\"counters\":{\"dns_query\":0,\"tcp_connection\":0,\"tls_handshake\":0,\"http_request\":0,\"redirect_target\":0,\"embedded_url\":0,\"proxy\":0,\"credential_path\":0},\"flags\":{\"tls_hostname_verified\":false,\"screened_peer_matched\":false,\"redirect_followed\":false,\"snapshot_authoritative\":false,\"stale_fallback_used\":false,\"consent_reusable\":false,\"credential_disturbed\":false},\"document_fingerprint\":\"none\",\"redirect_fingerprint\":\"none\",\"cleanup\":{\"processes_remaining\":${processes_remaining},\"containers_remaining\":${containers_remaining},\"networks_remaining\":${networks_remaining},\"temp_files_remaining\":${temp_files_remaining},\"private_keys_remaining\":${private_keys_remaining},\"hooks_remaining\":0,\"listeners_remaining\":${listeners_remaining}}}" | php "${validator}"
}

scan_private_file() {
	local path=$1

	if [[ ! -f "${path}" ]] || (( $(wc -c <"${path}") > 1048576 )); then
		return 1
	fi

	if LC_ALL=C grep -Eqi \
		-e '-----BEGIN [A-Z ]*PRIVATE KEY-----' \
		-e '(^|[^a-z])(authorization|proxy-authorization|cookie|set-cookie)[[:space:]]*[:=]' \
		-e '(Bearer|Basic)[[:space:]]+[A-Za-z0-9._~+/-]+' \
		-e '"(access_token|refresh_token|client_secret|authorization_code|password)"[[:space:]]*[:=]' \
		-e '(HTTP_PROXY|HTTPS_PROXY|ALL_PROXY|DATABASE_URL)[[:space:]]*=' \
		"${path}"; then
		return 1
	fi
}

cleanup_runtime() {
	local original_exit=${1:-0}
	local cleanup_failed=false
	local containers_remaining=0
	local networks_remaining=0
	local processes_remaining=0
	local listeners_remaining=0
	local container_ids=''
	local network_ids=''

	trap '' INT TERM

	if [[ true == "${p3_compose_started}" ]]; then
		if ! "${timeout_command}" --signal=TERM --kill-after=3 30 docker compose \
			--project-name "${p3_project_name}" --file "${compose_file}" \
			down --timeout 5 --volumes --remove-orphans >/dev/null 2>&1; then
			cleanup_failed=true
		fi
	fi

	if ! container_ids="$("${timeout_command}" --signal=TERM --kill-after=2 10 docker ps --all --quiet --filter "label=com.docker.compose.project=${p3_project_name}" 2>/dev/null)"; then
		cleanup_failed=true
		containers_remaining=1000
	else
		containers_remaining="$(printf '%s\n' "${container_ids}" | sed '/^$/d' | wc -l | tr -d ' ')"
	fi
	if ! network_ids="$("${timeout_command}" --signal=TERM --kill-after=2 10 docker network ls --quiet --filter "label=com.docker.compose.project=${p3_project_name}" 2>/dev/null)"; then
		cleanup_failed=true
		networks_remaining=1000
	else
		networks_remaining="$(printf '%s\n' "${network_ids}" | sed '/^$/d' | wc -l | tr -d ' ')"
	fi
	processes_remaining=${containers_remaining}
	listeners_remaining=${containers_remaining}

	if (( containers_remaining != 0 || networks_remaining != 0 )); then
		cleanup_failed=true
	fi

	find "${p3_cert_dir}" -type f -delete 2>/dev/null || cleanup_failed=true
	find "${p3_runtime_dir}" -type f -delete 2>/dev/null || cleanup_failed=true
	find "${p3_runtime_dir}" -depth -type d -empty -delete 2>/dev/null || cleanup_failed=true

	local temp_files_remaining=0
	local private_keys_remaining=0
	if [[ -e "${p3_runtime_dir}" ]]; then
		temp_files_remaining="$(find "${p3_runtime_dir}" -type f 2>/dev/null | wc -l | tr -d ' ')"
		private_keys_remaining="$(find "${p3_runtime_dir}" -type f -name '*.key' 2>/dev/null | wc -l | tr -d ' ')"
		cleanup_failed=true
	fi

	p3_cleanup_complete=true
	if [[ true == "${cleanup_failed}" ]]; then
		emit_record failed cleanup cleanup-incomplete cleanup cleanup-incomplete 0 \
			"${containers_remaining}" "${networks_remaining}" "${temp_files_remaining}" "${private_keys_remaining}" \
			"${processes_remaining}" "${listeners_remaining}" || true
		return 70
	fi

	emit_record passed cleanup cleanup-complete cleanup none 0
	return "${original_exit}"
}

on_exit() {
	local exit_code=$?

	trap - EXIT INT TERM
	if [[ false == "${p3_cleanup_complete}" ]]; then
		if [[ false == "${p3_failure_emitted}" && ${exit_code} -ne 0 ]]; then
			emit_record failed summary runner-stopped summary fixture-unavailable 0 || true
		fi
		cleanup_runtime "${exit_code}" || exit_code=$?
	fi

	exit "${exit_code}"
}

trap on_exit EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

run_private_gate() {
	local phase=$1
	local case_id=$2
	local runtime=$3
	shift 3

	local output="${p3_private_dir}/${case_id}.log"
	local started
	local finished
	local elapsed
	local exit_code

	started="$(php -r 'echo (int) round( microtime( true ) * 1000 );')"
	set +e
	if declare -F "$1" >/dev/null 2>&1; then
		(
			ulimit -S -f 2048
			"$@"
		) >"${output}" 2>&1
	else
		(
			ulimit -S -f 2048
			"${timeout_command}" --signal=TERM --kill-after=3 180 "$@"
		) >"${output}" 2>&1
	fi
	exit_code=$?
	set -e
	finished="$(php -r 'echo (int) round( microtime( true ) * 1000 );')"
	elapsed=$((finished - started))
	if (( elapsed > 300000 )); then
		elapsed=300000
	fi

	if ! scan_private_file "${output}"; then
		p3_failure_emitted=true
		emit_record failed "${phase}" "${case_id}" "${runtime}" schema-rejected "${elapsed}"
		return 1
	fi

	if (( exit_code != 0 )); then
		p3_failure_emitted=true
		emit_record failed "${phase}" "${case_id}" "${runtime}" test-failed "${elapsed}"
		return 1
	fi

	emit_record passed "${phase}" "${case_id}" "${runtime}" none "${elapsed}"
}

prepare_wordpress_source() {
	local archive="${p3_private_dir}/wordpress-6.9.5.zip"
	ulimit -S -f 81920 || return 1

	if ! env -u HTTP_PROXY -u HTTPS_PROXY -u ALL_PROXY \
		-u http_proxy -u https_proxy -u all_proxy \
		/usr/bin/curl --disable --silent --show-error --fail \
		--proto '=https' --proto-redir '=https' \
		--connect-timeout 5 --max-time 30 --max-filesize 41943040 \
		--output "${archive}" \
		https://downloads.w.org/release/wordpress-6.9.5.zip; then
		return 1
	fi

	if [[ ! -f "${archive}" ]] || (( $(wc -c <"${archive}") > 41943040 )); then
		return 1
	fi

	if ! unzip -q "${archive}" -d "${p3_runtime_dir}"; then
		return 1
	fi
	find "${p3_private_dir}" -name 'wordpress-6.9.5.zip' -type f -delete || return 1

	[[ -f "${p3_wordpress_root}/wp-includes/version.php" ]] || return 1
	php -r '$wp_version = null; require $argv[1]; exit( "6.9.5" === $wp_version ? 0 : 1 );' \
		"${p3_wordpress_root}/wp-includes/version.php"
}

assert_runtime_confinement() {
	local expected_network="${p3_project_name}_hostile"
	local container_id
	local binding_count
	local network_count
	local internal
	local control_ready=false
	local container_ids

	internal="$("${timeout_command}" --signal=TERM --kill-after=2 10 docker network inspect --format '{{.Internal}}' "${expected_network}" 2>/dev/null)"
	[[ true == "${internal}" ]] || return 1
	container_ids="$("${timeout_command}" --signal=TERM --kill-after=2 10 docker compose --project-name "${p3_project_name}" --file "${compose_file}" ps --quiet)"
	[[ 11 -eq $(printf '%s\n' "${container_ids}" | sed '/^$/d' | wc -l | tr -d ' ') ]] || return 1

	while IFS= read -r container_id; do
		[[ -n "${container_id}" ]] || continue
		binding_count="$("${timeout_command}" --signal=TERM --kill-after=2 10 docker inspect --format '{{len .HostConfig.PortBindings}}' "${container_id}")"
		network_count="$("${timeout_command}" --signal=TERM --kill-after=2 10 docker inspect --format '{{len .NetworkSettings.Networks}}' "${container_id}")"
		[[ 0 == "${binding_count}" && 1 == "${network_count}" ]] || return 1
		"${timeout_command}" --signal=TERM --kill-after=2 10 docker inspect --format '{{range $name, $_ := .NetworkSettings.Networks}}{{println $name}}{{end}}' "${container_id}" | grep -Eq "^${expected_network}$" || return 1
	done <<<"${container_ids}"

	for _ in {1..30}; do
		if "${timeout_command}" --signal=TERM --kill-after=2 3 docker compose \
			--project-name "${p3_project_name}" --file "${compose_file}" exec -T wp84 php -r '
			$context = stream_context_create( array( "http" => array( "timeout" => 2 ) ) );
			$body = @file_get_contents( getenv( "P3_FIXTURE_CONTROL_URL" ) . "/health", false, $context );
			$data = is_string( $body ) ? json_decode( $body, true ) : null;
			exit( is_array( $data ) && "ready" === ( $data["status"] ?? null ) ? 0 : 1 );
		' >/dev/null 2>&1; then
			control_ready=true
			break
		fi
		sleep 0.2
	done
	[[ true == "${control_ready}" ]] || return 1

	if "${timeout_command}" --signal=TERM --kill-after=2 10 docker compose \
		--project-name "${p3_project_name}" --file "${compose_file}" exec -T wp84 \
		php -r '$socket = @stream_socket_client( "tcp://1.1.1.1:443", $number, $message, 1 ); exit( false === $socket ? 0 : 1 );' >/dev/null 2>&1; then
		return 0
	fi

	return 1
}

assert_lane_capabilities() {
	local service=$1
	local expected_php=$2
	local output="${p3_private_dir}/${service}-capabilities.json"

	if ! "${timeout_command}" --signal=TERM --kill-after=2 30 docker compose \
		--project-name "${p3_project_name}" --file "${compose_file}" exec -T "${service}" php -r '
		$expectedPhp = $argv[1];
		require "/usr/src/wordpress/wp-includes/version.php";
		require "/usr/src/wordpress/wp-includes/Requests/src/Autoload.php";
		WpOrg\Requests\Autoload::register();
		$required = array(
			"CURLOPT_RESOLVE", "CURLOPT_PREREQFUNCTION", "CURLINFO_PRIMARY_IP",
			"CURLOPT_FRESH_CONNECT", "CURLOPT_FORBID_REUSE", "CURLOPT_ENCODING",
			"CURLOPT_PROXY", "CURLOPT_NOPROXY", "CURLOPT_HEADERFUNCTION",
			"CURLOPT_WRITEFUNCTION", "CURLOPT_TIMEOUT", "CURLOPT_CONNECTTIMEOUT",
			"CURLOPT_FOLLOWLOCATION", "CURLOPT_MAXREDIRS", "CURLOPT_SSL_VERIFYPEER",
			"CURLOPT_SSL_VERIFYHOST", "CURLOPT_CAINFO", "CURL_PREREQFUNC_OK",
			"CURL_PREREQFUNC_ABORT"
		);
		$constants = true;
		foreach ( $required as $name ) { $constants = $constants && defined( $name ); }
		$curl = extension_loaded( "curl" ) ? curl_version() : array();
		$ok = str_starts_with( PHP_VERSION, $expectedPhp . "." )
			&& "6.9.5" === $wp_version
			&& "2.0.11" === WpOrg\Requests\Requests::VERSION
			&& extension_loaded( "curl" )
			&& version_compare( (string) ( $curl["version"] ?? "0" ), "7.80.0", ">=" )
			&& $constants;
		echo json_encode( array( "ok" => $ok, "php" => $expectedPhp, "wordpress" => "6.9.5", "requests" => "2.0.11", "curl_controls" => $constants ) );
		exit( $ok ? 0 : 1 );
	' "${expected_php}" >"${output}" 2>&1; then
		return 1
	fi

	scan_private_file "${output}"
}

assert_fixture_listeners() {
	"${timeout_command}" --signal=TERM --kill-after=2 30 docker compose \
		--project-name "${p3_project_name}" --file "${compose_file}" exec -T wp84 php -r '
		$plainTargets = array(
			"tcp://198.17.0.53:53", "tcp://198.17.0.40:8080", "tcp://198.17.0.41:1080"
		);
		foreach ( $plainTargets as $target ) {
			$socket = @stream_socket_client( $target, $number, $message, 2 );
			if ( false === $socket ) { exit( 1 ); }
			fclose( $socket );
		}

		$context = stream_context_create(
			array(
				"ssl" => array(
					"cafile"            => getenv( "P3_FIXTURE_CA_FILE" ),
					"peer_name"         => "client.charter.test",
					"verify_peer"       => true,
					"verify_peer_name"  => true,
					"allow_self_signed" => false,
				),
			)
		);
		$tlsTargets = array(
			"tls://198.17.0.34:443", "tls://198.17.0.35:443",
			"tls://198.17.0.36:443", "tls://198.18.0.10:443",
			"tls://[2001:4860:ffff::34]:443"
		);
		$request = "GET /client.json HTTP/1.1\r\n"
			. "Host: client.charter.test\r\n"
			. "Accept: application/json\r\n"
			. "Accept-Encoding: identity\r\n"
			. "Cache-Control: no-cache\r\n"
			. "User-Agent: Charter-P3-Probe/1\r\n"
			. "Connection: close\r\n\r\n";
		foreach ( $tlsTargets as $target ) {
			$socket = @stream_socket_client( $target, $number, $message, 2, STREAM_CLIENT_CONNECT, $context );
			if ( false === $socket ) { exit( 1 ); }
			stream_set_timeout( $socket, 2 );
			if ( strlen( $request ) !== @fwrite( $socket, $request ) ) { fclose( $socket ); exit( 1 ); }
			$response = @fread( $socket, 128 );
			fclose( $socket );
			if ( ! is_string( $response ) || ! str_starts_with( $response, "HTTP/1.1 200 " ) ) { exit( 1 ); }
		}

		$observed = false;
		for ( $attempt = 0; $attempt < 30; ++$attempt ) {
			$body = @file_get_contents( getenv( "P3_FIXTURE_CONTROL_URL" ) . "/counters" );
			$data = is_string( $body ) ? json_decode( $body, true ) : null;
			$counters = is_array( $data ) ? ( $data["counters"] ?? null ) : null;
			if ( is_array( $counters ) && ( $counters["tcp_connection"] ?? 0 ) >= 4 && ( $counters["proxy"] ?? 0 ) >= 2 ) {
				$observed = true;
				break;
			}
			usleep( 100000 );
		}
		if ( ! $observed ) { exit( 1 ); }
		$context = stream_context_create( array( "http" => array( "method" => "POST", "timeout" => 2 ) ) );
		$body = @file_get_contents( getenv( "P3_FIXTURE_CONTROL_URL" ) . "/scenario/safe", false, $context );
		$data = is_string( $body ) ? json_decode( $body, true ) : null;
		exit( is_array( $data ) && "safe" === ( $data["scenario"] ?? null ) ? 0 : 1 );
	'
}

emit_fixture_counters() {
	local phase=$1
	local case_id=$2
	local runtime=$3
	local output="${p3_private_dir}/${case_id}-counters.json"

	"${timeout_command}" --signal=TERM --kill-after=2 10 docker compose \
		--project-name "${p3_project_name}" --file "${compose_file}" exec -T wp84 php -r '
		$body = @file_get_contents( getenv( "P3_FIXTURE_CONTROL_URL" ) . "/counters" );
		if ( ! is_string( $body ) || strlen( $body ) > 8192 ) { exit( 1 ); }
		echo $body;
	' >"${output}" 2>/dev/null
	php "${validator}" --counter-capture "${output}" "${phase}" "${case_id}-counters" "${runtime}"
}

render_compose_config() {
	"${timeout_command}" --signal=TERM --kill-after=2 30 docker compose \
		--project-name "${p3_project_name}" --file "${compose_file}" \
		config --format json >"${p3_private_dir}/compose.json"
}

run_phpunit_lane() {
	local service=$1
	local runtime=$2
	local mode=$3
	local case_id="${service}-${mode}"
	local phpunit=(php vendor/bin/phpunit --configuration=phpunit.xml.dist --bootstrap=tests/fixtures/cimd-outbound-safety/bootstrap-wordpress-http.php --do-not-cache-result --group=p3-hostile)

	if [[ fresh == "${mode}" ]]; then
		run_private_gate hostile "${case_id}" "${runtime}" docker compose \
			--project-name "${p3_project_name}" --file "${compose_file}" \
			exec -T "${service}" "${phpunit[@]}" --process-isolation tests/Integration/CimdOutboundSafety
	else
		run_private_gate hostile "${case_id}" "${runtime}" docker compose \
			--project-name "${p3_project_name}" --file "${compose_file}" \
			exec -T "${service}" "${phpunit[@]}" tests/Integration/CimdOutboundSafety
	fi

	if ! LC_ALL=C grep -Eq 'OK \([1-9][0-9]* tests?,' "${p3_private_dir}/${case_id}.log"; then
		p3_failure_emitted=true
		emit_record failed hostile "${case_id}-empty" "${runtime}" test-failed 0
		return 1
	fi

	emit_fixture_counters hostile "${case_id}" "${runtime}"
}

run_fixture_probe() {
	local mode=$1
	local phase=$2
	local case_id="fixture-${mode}"

	run_private_gate "${phase}" "${case_id}" wordpress-php84-direct docker compose \
		--project-name "${p3_project_name}" --file "${compose_file}" \
		exec -T wp84 php /workspace/tests/fixtures/cimd-outbound-safety/client/probe.php "${mode}"
	emit_fixture_counters "${phase}" "${case_id}" wordpress-php84-direct
}

run_stock_wordpress_expected_red() {
	local case_id=expected-red-stock-wordpress-rebind

	run_private_gate hostile "${case_id}" wordpress-php84-direct docker compose \
		--project-name "${p3_project_name}" --file "${compose_file}" \
		exec -T wp84 php /workspace/tests/fixtures/cimd-outbound-safety/client/stock-wordpress-red.php
	emit_fixture_counters hostile "${case_id}" wordpress-php84-direct
}

interrupt_owned_service() {
	local service=$1
	local case_id="owned-${service}-interruption"
	local lookup_log="${p3_private_dir}/${case_id}-lookup.log"
	local inspect_log="${p3_private_dir}/${case_id}-inspect.log"
	local container_id=''
	local project_label=''
	local lookup_exit=0

	set +e
	container_id="$("${timeout_command}" --signal=TERM --kill-after=2 20 docker compose \
		--project-name "${p3_project_name}" --file "${compose_file}" \
		ps --quiet "${service}" 2>"${lookup_log}")"
	lookup_exit=$?
	set -e

	if ! scan_private_file "${lookup_log}"; then
		p3_failure_emitted=true
		emit_record failed interruption "${case_id}" interruption schema-rejected 0
		return 1
	fi

	if (( lookup_exit == 0 )) && [[ -n "${container_id}" ]]; then
		project_label="$("${timeout_command}" --signal=TERM --kill-after=2 10 docker inspect \
			--format '{{index .Config.Labels "com.docker.compose.project"}}' "${container_id}" \
			2>"${inspect_log}")" || project_label=''
	fi

	if [[ -f "${inspect_log}" ]] && ! scan_private_file "${inspect_log}"; then
		p3_failure_emitted=true
		emit_record failed interruption "${case_id}" interruption schema-rejected 0
		return 1
	fi

	if [[ -z "${container_id}" ]] || [[ "${p3_project_name}" != "${project_label}" ]]; then
		p3_failure_emitted=true
		emit_record failed interruption "${case_id}" interruption interrupted 0
		return 1
	fi

	run_private_gate interruption "${case_id}-stop" interruption docker stop --time 1 "${container_id}"
	run_private_gate interruption "${case_id}-remove" interruption docker rm "${container_id}"
	emit_record passed interruption "${case_id}" interruption none 0
}

run_retained_p2_protected_request() {
	local gate_exit=0
	local resolved_core=''
	ulimit -S -f 131072 || return 1

	resolved_core="$(bash "${project_root}/tools/resolve-wordpress-core.sh")" || return 1
	export WORDPRESS_BRANCH=6.9
	export WP_ENV_CORE="${resolved_core}"

	set +e
	"${timeout_command}" --signal=TERM --kill-after=5 180 npm run test:slice0:multisite:destroy >/dev/null 2>&1
	"${timeout_command}" --signal=TERM --kill-after=5 240 npm run test:slice0:multisite:start || gate_exit=$?
	if (( gate_exit == 0 )); then
		"${timeout_command}" --signal=TERM --kill-after=5 120 npm run test:slice0:multisite:prepare || gate_exit=$?
	fi
	if (( gate_exit == 0 )); then
		"${timeout_command}" --signal=TERM --kill-after=5 60 npm run test:slice0:multisite:version || gate_exit=$?
	fi
	if (( gate_exit == 0 )); then
		"${timeout_command}" --signal=TERM --kill-after=5 180 "${project_root}/node_modules/.bin/wp-env" run cli --config=.wp-env.slice0.json \
			--env-cwd=wp-content/plugins/charter php vendor/bin/phpunit \
			--configuration=phpunit.xml.dist --bootstrap=tests/bootstrap-integration.php \
			--do-not-cache-result tests/Integration/CimdOutboundSafety/CredentialIsolationWordPressTest.php || gate_exit=$?
	fi
	"${timeout_command}" --signal=TERM --kill-after=5 180 npm run test:slice0:multisite:destroy || gate_exit=$?
	set -e

	return "${gate_exit}"
}

if [[ -z "${timeout_command}" ]]; then
	p3_failure_emitted=true
	emit_record failed preflight timeout-command static capability-unavailable 0
	exit 1
fi

for command_name in curl docker grep openssl php unzip; do
	if ! command -v "${command_name}" >/dev/null 2>&1; then
		p3_failure_emitted=true
		emit_record failed preflight required-command static capability-unavailable 0
		exit 1
	fi
done

run_private_gate preflight wordpress-source static prepare_wordpress_source
run_private_gate preflight tls-generation static \
	"${project_root}/tests/fixtures/cimd-outbound-safety/tls/generate.sh" "${p3_cert_dir}"
run_private_gate preflight state-initialization static env P3_STATE_DIR="${p3_state_dir}" php -r \
	'require $argv[1]; charter_p3_reset( "safe" );' \
	"${project_root}/tests/fixtures/cimd-outbound-safety/state.php"
run_private_gate preflight state-permissions static chmod 666 "${p3_state_dir}"/counters.json "${p3_state_dir}"/scenario "${p3_state_dir}"/state.lock
run_private_gate preflight compose-render static render_compose_config
php "${validator}" --compose-config "${p3_private_dir}/compose.json"

run_private_gate pure pure-matrix pure-php \
	php vendor/bin/phpunit --configuration=phpunit.xml.dist --bootstrap=tests/bootstrap-unit.php \
	--do-not-cache-result --exclude-group=p3-hostile tests/Integration/CimdOutboundSafety
run_private_gate retained p2-protected-request wordpress-p2 run_retained_p2_protected_request

p3_compose_started=true
run_private_gate preflight compose-up static docker compose \
	--project-name "${p3_project_name}" --file "${compose_file}" up --detach

run_private_gate preflight runtime-confinement static assert_runtime_confinement
run_private_gate preflight fixture-listeners static assert_fixture_listeners
run_private_gate preflight php84-capabilities wordpress-php84-direct assert_lane_capabilities wp84 8.4
run_private_gate preflight php85-capabilities wordpress-php85-direct assert_lane_capabilities wp85 8.5

run_fixture_probe direct hostile
run_fixture_probe expected-red-rebind hostile
run_stock_wordpress_expected_red
run_fixture_probe rebind hostile
run_fixture_probe redirect hostile
run_fixture_probe connect-timeout timeout
run_fixture_probe tls-timeout timeout
run_fixture_probe timeout timeout
run_fixture_probe limit limit
run_fixture_probe expected-red-proxy-http proxy
run_fixture_probe expected-red-proxy-connect proxy
run_fixture_probe expected-red-proxy-socks-local proxy
run_fixture_probe expected-red-proxy-socks-remote proxy

run_phpunit_lane wp84 wordpress-php84-direct fresh
run_phpunit_lane wp84 wordpress-php84-reused reused
run_phpunit_lane wp84 wordpress-php84-reused reused
run_phpunit_lane wp85 wordpress-php85-direct fresh
run_phpunit_lane wp85 wordpress-php85-reused reused
run_phpunit_lane wp85 wordpress-php85-reused reused

for interruption_service in dns origin origin6 http-proxy socks-proxy wp84 wp85; do
	interrupt_owned_service "${interruption_service}"
done

cleanup_runtime 0
emit_record passed summary p3-hostile-matrix summary none 0
