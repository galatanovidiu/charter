#!/usr/bin/env bash

set -euo pipefail

project_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
compose_file="${project_root}/tests/fixtures/discovery-publication/docker-compose.yml"
timeout_command="$(command -v gtimeout || command -v timeout || true)"

if [[ -z "${timeout_command}" ]]; then
	printf 'P5 runner requires GNU timeout or gtimeout.\n' >&2
	exit 1
fi

p5_runtime_dir="$(mktemp -d /tmp/charter-p5-discovery.XXXXXX)"
p5_private_dir="${p5_runtime_dir}/private"
p5_server_cert_dir="${p5_runtime_dir}/server-certs"
p5_client_cert_dir="${p5_runtime_dir}/client-certs"
p5_http_capture_dir="${p5_runtime_dir}/http-captures"
p5_state_dir="${p5_runtime_dir}/state"
p5_wordpress_root="${p5_runtime_dir}/wordpress"
p5_project_name="charter-p5-$$-${RANDOM}"
p5_host_uid="$(id -u)"
p5_host_gid="$(id -g)"
capture_counter=0
p5_compose_started=false
p5_emit_failure_logs=true
p5_process_mode=fresh

install -d -m 700 "${p5_private_dir}" "${p5_server_cert_dir}" "${p5_client_cert_dir}" "${p5_http_capture_dir}"
install -d -m 755 "${p5_state_dir}"

export P5_PROJECT_ROOT="${project_root}"
export P5_SERVER_CERT_DIR="${p5_server_cert_dir}"
export P5_CLIENT_CERT_DIR="${p5_client_cert_dir}"
export P5_HTTP_CAPTURE_DIR="${p5_http_capture_dir}"
export P5_STATE_DIR="${p5_state_dir}"
export P5_WORDPRESS_ROOT="${p5_wordpress_root}"
export P5_ISSUER="https://issuer.charter.test"
export P5_HOST_UID="${p5_host_uid}"
export P5_HOST_GID="${p5_host_gid}"

allocate_loopback_port() {
	php -r '
		$socket = stream_socket_server( "tcp://127.0.0.1:0", $error_number, $error_message );
		if ( false === $socket ) {
			fwrite( STDERR, "Unable to allocate a loopback proof port.\n" );
			exit( 1 );
		}
		$name = stream_socket_get_name( $socket, false );
		fclose( $socket );
		echo substr( $name, strrpos( $name, ":" ) + 1 );
	'
}

export P5_APACHE_PORT="$(allocate_loopback_port)"
export P5_NGINX_PORT="$(allocate_loopback_port)"
export P5_PROXY_PORT="$(allocate_loopback_port)"
export P5_DOT_DENY_PORT="$(allocate_loopback_port)"
export P5_PHYSICAL_WELL_KNOWN_PORT="$(allocate_loopback_port)"
export P5_INTERCEPT_REDIRECT_PORT="$(allocate_loopback_port)"
export P5_INTERCEPT_JSON_PORT="$(allocate_loopback_port)"
export P5_HTML_FALLBACK_PORT="$(allocate_loopback_port)"

compose() {
	docker compose --project-name "${p5_project_name}" --file "${compose_file}" "$@"
}

cleanup() {
	local exit_code=$?
	local cleanup_failed=false

	trap '' INT TERM
	trap - EXIT

	if ! find "${p5_private_dir}" "${p5_server_cert_dir}" "${p5_client_cert_dir}" -type f -delete 2>/dev/null; then
		cleanup_failed=true
	fi

	if (( exit_code != 0 )) && [[ true == "${p5_compose_started}" ]] && [[ true == "${p5_emit_failure_logs}" ]]; then
		"${timeout_command}" --signal=TERM --kill-after=2 10 docker compose \
			--project-name "${p5_project_name}" --file "${compose_file}" \
			logs --no-color --tail=80 || true
	fi

	if ! "${timeout_command}" --signal=TERM --kill-after=2 20 docker compose \
		--project-name "${p5_project_name}" --file "${compose_file}" \
		down --timeout 5 --volumes --remove-orphans >/dev/null 2>&1; then
		cleanup_failed=true
	fi

	if ! find "${p5_runtime_dir}" -type f -delete 2>/dev/null; then
		cleanup_failed=true
	fi

	if ! find "${p5_runtime_dir}" -depth -type d -empty -delete 2>/dev/null; then
		cleanup_failed=true
	fi

	if [[ true == "${cleanup_failed}" ]]; then
		printf '{"status":"failed","phase":"cleanup","reason_code":"incomplete_cleanup"}\n' >&2
		exit_code=70
	fi

	exit "${exit_code}"
}

trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

set_runtime_state() {
	local state=$1

	php -r 'file_put_contents($argv[1], $argv[2] . PHP_EOL);' "${p5_state_dir}/current" "${state}"
	chmod 644 "${p5_state_dir}/current"
}

set_runtime_state prepared

generate_certificates() {
	openssl req -x509 -newkey rsa:2048 -nodes \
		-keyout "${p5_private_dir}/ca.key" \
		-out "${p5_server_cert_dir}/ca.crt" \
		-subj '/CN=Charter P5 Proof CA' \
		-days 1 >/dev/null 2>&1
	openssl req -new -newkey rsa:2048 -nodes \
		-keyout "${p5_server_cert_dir}/server.crt.key" \
		-out "${p5_private_dir}/server.csr" \
		-subj '/CN=issuer.charter.test' \
		-addext 'subjectAltName=DNS:issuer.charter.test,DNS:sibling.charter.test,DNS:path-network.charter.test,IP:127.0.0.1' >/dev/null 2>&1
	openssl x509 -req \
		-in "${p5_private_dir}/server.csr" \
		-CA "${p5_server_cert_dir}/ca.crt" \
		-CAkey "${p5_private_dir}/ca.key" \
		-CAserial "${p5_private_dir}/ca.srl" \
		-CAcreateserial \
		-copy_extensions copy \
		-out "${p5_server_cert_dir}/server.crt" \
		-days 1 >/dev/null 2>&1
	openssl x509 -in "${p5_server_cert_dir}/ca.crt" -out "${p5_client_cert_dir}/ca.crt" >/dev/null 2>&1
	chmod 600 "${p5_private_dir}/ca.key" "${p5_server_cert_dir}/server.crt.key"
	chmod 644 \
		"${p5_server_cert_dir}/ca.crt" \
		"${p5_server_cert_dir}/server.crt" \
		"${p5_client_cert_dir}/ca.crt"
}

prepare_wordpress_source() {
	local archive="${p5_private_dir}/wordpress-6.9.5.zip"

	env -u HTTP_PROXY -u HTTPS_PROXY -u ALL_PROXY \
		-u http_proxy -u https_proxy -u all_proxy \
		/usr/bin/curl --disable --silent --show-error --fail \
		--connect-timeout 5 --max-time 30 --max-filesize 41943040 \
		--output "${archive}" \
		https://downloads.w.org/release/wordpress-6.9.5.zip
	unzip -q "${archive}" -d "${p5_runtime_dir}"
	find "${p5_private_dir}" -name 'wordpress-6.9.5.zip' -type f -delete
	php -r 'include $argv[1]; exit("6.9.5" === $wp_version ? 0 : 1);' "${p5_wordpress_root}/wp-includes/version.php"
}

container_id() {
	local service=$1
	local id

	id="$(docker ps \
		--filter "label=com.docker.compose.project=${p5_project_name}" \
		--filter "label=com.docker.compose.service=${service}" \
		--format '{{.ID}}')"

	if [[ -z "${id}" ]]; then
		printf 'P5 runner could not resolve service %s.\n' "${service}" >&2
		return 1
	fi

	printf '%s\n' "${id}"
}

edge_ip() {
	local service=$1
	local id
	local ip

	id="$(container_id "${service}")"
	ip="$(docker inspect --format '{{range $name, $network := .NetworkSettings.Networks}}{{printf "%s %s\n" $name $network.IPAddress}}{{end}}' "${id}" | awk '$1 ~ /client-edge$/ { print $2 }')"

	if [[ -z "${ip}" ]]; then
		printf 'P5 runner could not resolve the client-edge address for %s.\n' "${service}" >&2
		return 1
	fi

	printf '%s\n' "${ip}"
}

assert_network_boundaries() {
	local service
	local id
	local binding
	local expected_port
	local relay_port
	local client_networks
	local backend_networks
	local network
	local relay_id
	local relay_mounts
	local host_edge_members

	for service in apache nginx proxy dot-deny physical-well-known intercept-redirect intercept-json html-fallback; do
		id="$(container_id "${service}")"
		binding="$(docker port "${id}")"

		if [[ -n "${binding}" ]]; then
			printf 'P5 runner rejected direct host publication for %s.\n' "${service}" >&2
			return 1
		fi
	done

	relay_id="$(container_id host-relay)"

	for relay_port in 8443 8444 8445 8446 8447 8448 8449 8450; do
		case "${relay_port}" in
			8443) expected_port="${P5_APACHE_PORT}" ;;
			8444) expected_port="${P5_NGINX_PORT}" ;;
			8445) expected_port="${P5_PROXY_PORT}" ;;
			8446) expected_port="${P5_DOT_DENY_PORT}" ;;
			8447) expected_port="${P5_PHYSICAL_WELL_KNOWN_PORT}" ;;
			8448) expected_port="${P5_INTERCEPT_REDIRECT_PORT}" ;;
			8449) expected_port="${P5_INTERCEPT_JSON_PORT}" ;;
			8450) expected_port="${P5_HTML_FALLBACK_PORT}" ;;
		esac

		binding="$(docker inspect --format "{{with index .HostConfig.PortBindings \"${relay_port}/tcp\"}}{{(index . 0).HostIp}}:{{(index . 0).HostPort}}{{end}}" "${relay_id}")"

		if [[ "127.0.0.1:${expected_port}" != "${binding}" ]]; then
			printf 'P5 runner rejected loopback relay binding %s.\n' "${relay_port}" >&2
			return 1
		fi
	done

	client_networks="$(docker inspect --format '{{range $name, $network := .NetworkSettings.Networks}}{{println $name}}{{end}}' "$(container_id client)")"
	backend_networks="$(docker inspect --format '{{range $name, $network := .NetworkSettings.Networks}}{{println $name}}{{end}}' "$(container_id fpm)")"

	if ! grep -Eq 'client-edge$' <<<"${client_networks}" || grep -Eq 'backend$' <<<"${client_networks}"; then
		printf 'P5 runner rejected the client network membership.\n' >&2
		return 1
	fi

	if ! grep -Eq 'backend$' <<<"${backend_networks}" || grep -Eq 'client-edge$' <<<"${backend_networks}"; then
		printf 'P5 runner rejected the backend network membership.\n' >&2
		return 1
	fi

	for network in client-edge backend; do
		if [[ true != "$(docker network inspect --format '{{.Internal}}' "${p5_project_name}_${network}")" ]]; then
			printf 'P5 runner rejected non-internal network %s.\n' "${network}" >&2
			return 1
		fi
	done

	if [[ false != "$(docker network inspect --format '{{.Internal}}' "${p5_project_name}_host-edge")" ]]; then
		printf 'P5 runner rejected the loopback relay host network.\n' >&2
		return 1
	fi

	host_edge_members="$(docker network inspect --format '{{range .Containers}}{{println .Name}}{{end}}' "${p5_project_name}_host-edge")"

	if [[ "${p5_project_name}-host-relay-1" != "${host_edge_members}" ]]; then
		printf 'P5 runner rejected unexpected host-network membership.\n' >&2
		return 1
	fi

	relay_mounts="$(docker inspect --format '{{range .Mounts}}{{println .Source}}{{end}}' "${relay_id}")"

	if grep -Eq '/workspace$|/certs$|http-captures|/wordpress$' <<<"${relay_mounts}"; then
		printf 'P5 runner rejected sensitive loopback relay mounts.\n' >&2
		return 1
	fi

	if docker exec "$(container_id client)" curl --disable --silent --connect-timeout 1 --max-time 2 http://fpm:9000 >/dev/null 2>&1; then
		printf 'P5 runner reached a backend directly from the external client.\n' >&2
		return 1
	fi
}

capture_request() {
	local lane=$1
	local state=$2
	local service=$3
	local path=$4
	local expected_status=$5
	local expected_identity=$6
	local expected_reached=$7
	shift 7

	local ip
	local capture_name
	local requested_url

	ip="$(edge_ip "${service}")"
	capture_counter=$((capture_counter + 1))
	capture_name="capture-${capture_counter}"
	requested_url="${P5_ISSUER}${path}"

	docker exec "$(container_id client)" curl --disable --silent --show-error \
		--request GET \
		--header 'Accept: application/json' \
		--connect-timeout 3 \
		--max-time 8 \
		--max-filesize 65536 \
		--max-redirs 0 \
		--cacert /certs/ca.crt \
		--resolve "issuer.charter.test:443:${ip}" \
		--dump-header "/capture/${capture_name}.headers" \
		--output "/capture/${capture_name}.body" \
		"$@" \
		"${requested_url}"

	php "${project_root}/tools/validate-slice0-discovery-publication-output.php" \
		--lane="${lane}" \
		--state="${state}" \
		--process-mode="${p5_process_mode}" \
		--url="${requested_url}" \
		--expected-status="${expected_status}" \
		--expected-identity="${expected_identity}" \
		--expected-reached="${expected_reached}" \
		--headers="${p5_http_capture_dir}/${capture_name}.headers" \
		--body="${p5_http_capture_dir}/${capture_name}.body"
}

capture_plain_http_rejection() {
	local service=apache
	local ip
	local capture_name
	local requested_url='http://issuer.charter.test/.well-known/oauth-authorization-server'

	ip="$(edge_ip "${service}")"
	capture_counter=$((capture_counter + 1))
	capture_name="capture-${capture_counter}"

	docker exec "$(container_id client)" curl --disable --silent --show-error \
		--request GET \
		--header 'Accept: application/json' \
		--connect-timeout 3 \
		--max-time 8 \
		--max-filesize 65536 \
		--max-redirs 0 \
		--resolve "issuer.charter.test:80:${ip}" \
		--dump-header "/capture/${capture_name}.headers" \
		--output "/capture/${capture_name}.body" \
		"${requested_url}"

	php "${project_root}/tools/validate-slice0-discovery-publication-output.php" \
		--lane=wrong-scheme \
		--state=prepared \
		--process-mode="${p5_process_mode}" \
		--url="${requested_url}" \
		--expected-status=403 \
		--expected-identity='' \
		--expected-reached=false \
		--headers="${p5_http_capture_dir}/${capture_name}.headers" \
		--body="${p5_http_capture_dir}/${capture_name}.body"
}

host_capture_request() {
	local capture_name
	local requested_url="${P5_ISSUER}/.well-known/oauth-authorization-server"

	capture_counter=$((capture_counter + 1))
	capture_name="capture-${capture_counter}"

	env -u HTTP_PROXY -u HTTPS_PROXY -u ALL_PROXY \
		-u http_proxy -u https_proxy -u all_proxy \
		/usr/bin/curl --disable --silent --show-error \
		--request GET \
		--header 'Accept: application/json' \
		--connect-timeout 3 \
		--max-time 8 \
		--max-filesize 65536 \
		--max-redirs 0 \
		--cacert "${p5_client_cert_dir}/ca.crt" \
		--connect-to "issuer.charter.test:443:127.0.0.1:${P5_APACHE_PORT}" \
		--dump-header "${p5_http_capture_dir}/${capture_name}.headers" \
		--output "${p5_http_capture_dir}/${capture_name}.body" \
		"${requested_url}"

	php "${project_root}/tools/validate-slice0-discovery-publication-output.php" \
		--lane=host-cli \
		--state=prepared \
		--process-mode="${p5_process_mode}" \
		--url="${requested_url}" \
		--expected-status=200 \
		--expected-identity="${P5_ISSUER}" \
		--expected-reached=true \
		--headers="${p5_http_capture_dir}/${capture_name}.headers" \
		--body="${p5_http_capture_dir}/${capture_name}.body"
}

wait_for_service() {
	local service=$1
	local ip
	local attempt
	local status

	for attempt in {1..30}; do
		ip="$(edge_ip "${service}")"

		if status="$(docker exec "$(container_id client)" curl --disable --silent \
			--connect-timeout 1 --max-time 2 \
			--cacert /certs/ca.crt \
			--resolve "issuer.charter.test:443:${ip}" \
			--output /dev/null \
			--write-out '%{http_code}' \
			"${P5_ISSUER}/.well-known/oauth-authorization-server" 2>/dev/null)"; then
			if [[ "${status}" =~ ^[234][0-9][0-9]$ ]]; then
				return 0
			fi
		fi

		sleep 1
	done

	printf 'P5 service %s did not become ready.\n' "${service}" >&2
	return 1
}

run_manual_url() {
	local manual_url=$1
	local expected_identity
	local capture_name='manual-capture'

	expected_identity="$(php -r '
		require $argv[1] . "/vendor/autoload.php";
		$url   = $argv[2];
		$parts = parse_url( $url );

		if ( ! is_array( $parts ) || ! isset( $parts["scheme"], $parts["host"], $parts["path"] ) ) {
			exit( 1 );
		}

		$issuer = $parts["scheme"] . "://" . $parts["host"];

		if ( isset( $parts["port"] ) ) {
			$issuer .= ":" . $parts["port"];
		}

		$path = $parts["path"];

		if ( "/.well-known/oauth-authorization-server" === $path ) {
			$expectedUrl = GalatanOvidiu\Charter\Tests\Prototype\DiscoveryPublication\MetadataProjector::authorizationServerUrl( $issuer );
			$identity    = $issuer;
		} elseif ( "/.well-known/oauth-protected-resource" === $path ) {
			$expectedUrl = GalatanOvidiu\Charter\Tests\Prototype\DiscoveryPublication\MetadataProjector::protectedResourceUrl( $issuer, $issuer );
			$identity    = $issuer;
		} elseif ( str_starts_with( $path, "/.well-known/oauth-protected-resource/" ) ) {
			$resourcePath = substr( $path, strlen( "/.well-known/oauth-protected-resource" ) );
			$identity     = $issuer . $resourcePath;
			$expectedUrl  = GalatanOvidiu\Charter\Tests\Prototype\DiscoveryPublication\MetadataProjector::protectedResourceUrl( $issuer, $identity );
		} else {
			exit( 1 );
		}

		if ( $expectedUrl !== $url ) {
			exit( 1 );
		}

		echo $identity;
	' "${project_root}" "${manual_url}")" || {
		printf 'P5 manual URL must be an exact supported HTTPS discovery URL.\n' >&2
		return 1
	}

	env -u HTTP_PROXY -u HTTPS_PROXY -u ALL_PROXY \
		-u http_proxy -u https_proxy -u all_proxy \
		/usr/bin/curl --disable --silent --show-error --fail-with-body \
		--proto '=https' --request GET --header 'Accept: application/json' \
		--connect-timeout 5 --max-time 10 --max-filesize 65536 \
		--max-redirs 0 \
		--dump-header "${p5_http_capture_dir}/${capture_name}.headers" \
		--output "${p5_http_capture_dir}/${capture_name}.body" \
		"${manual_url}"

	php "${project_root}/tools/validate-slice0-discovery-publication-output.php" \
		--lane=manual-cli \
		--state=prepared \
		--process-mode="${p5_process_mode}" \
		--url="${manual_url}" \
		--expected-status=200 \
		--expected-identity="${expected_identity}" \
		--expected-reached=any \
		--headers="${p5_http_capture_dir}/${capture_name}.headers" \
		--body="${p5_http_capture_dir}/${capture_name}.body"
}

run_browser_session() {
	local capture_name='browser-capture'
	local requested_url
	local attempt
	local p5_browser_command

	export P5_ISSUER="https://127.0.0.1:${P5_APACHE_PORT}"
	requested_url="${P5_ISSUER}/.well-known/oauth-authorization-server"

	generate_certificates
	prepare_wordpress_source
	compose config --quiet
	compose up --detach --no-deps apache host-relay >/dev/null
	p5_compose_started=true

	for attempt in {1..30}; do
		if env -u HTTP_PROXY -u HTTPS_PROXY -u ALL_PROXY \
			-u http_proxy -u https_proxy -u all_proxy \
			/usr/bin/curl --disable --silent --show-error --fail \
			--connect-timeout 1 --max-time 2 \
			--cacert "${p5_client_cert_dir}/ca.crt" \
			--output /dev/null \
			"${requested_url}"; then
			break
		fi

		if [[ 30 -eq "${attempt}" ]]; then
			printf 'P5 browser proof server did not become ready.\n' >&2
			return 1
		fi

		sleep 1
	done

	env -u HTTP_PROXY -u HTTPS_PROXY -u ALL_PROXY \
		-u http_proxy -u https_proxy -u all_proxy \
		/usr/bin/curl --disable --silent --show-error --fail-with-body \
		--proto '=https' --request GET --header 'Accept: application/json' \
		--connect-timeout 5 --max-time 10 --max-filesize 65536 \
		--max-redirs 0 \
		--cacert "${p5_client_cert_dir}/ca.crt" \
		--dump-header "${p5_http_capture_dir}/${capture_name}.headers" \
		--output "${p5_http_capture_dir}/${capture_name}.body" \
		"${requested_url}"

	php "${project_root}/tools/validate-slice0-discovery-publication-output.php" \
		--lane=browser-host \
		--state=prepared \
		--process-mode="${p5_process_mode}" \
		--url="${requested_url}" \
		--expected-status=200 \
		--expected-identity="${P5_ISSUER}" \
		--expected-reached=true \
		--headers="${p5_http_capture_dir}/${capture_name}.headers" \
		--body="${p5_http_capture_dir}/${capture_name}.body"
	printf '{"browser_session":"ready","url":"%s","trust":"proof-owned-ca"}\n' "${requested_url}"

	while true; do
		if ! IFS= read -r -t 600 p5_browser_command; then
			printf 'P5 browser proof session reached its finite wait limit.\n' >&2
			return 1
		fi

		if [[ stop == "${p5_browser_command}" ]]; then
			return 0
		fi
	done
}

run_state_matrix() {
	local state=$1
	local process_mode=$2
	local metadata_status
	local operation_status
	local metadata_identity
	local isolated_identity
	local operation_identity
	local service

	set_runtime_state "${state}"
	p5_process_mode="${process_mode}"

	if [[ fresh == "${process_mode}" ]]; then
		compose up --detach --no-deps --force-recreate apache fpm nginx proxy-origin proxy >/dev/null
	elif [[ reused != "${process_mode}" ]]; then
		printf 'P5 runner received an unknown process mode.\n' >&2
		return 1
	fi

	for service in apache nginx proxy; do
		wait_for_service "${service}"
	done

	case "${state}" in
		available)
			metadata_status=404
			operation_status=404
			metadata_identity=''
			isolated_identity=''
			operation_identity=''
			;;
		prepared)
			metadata_status=200
			operation_status=403
			metadata_identity="${P5_ISSUER}"
			isolated_identity="${P5_ISSUER}/integrations/example"
			operation_identity=''
			;;
		enabled)
			metadata_status=200
			operation_status=200
			metadata_identity="${P5_ISSUER}"
			isolated_identity="${P5_ISSUER}/integrations/example"
			operation_identity="${P5_ISSUER}"
			;;
		*)
			printf 'P5 runner received an unknown state.\n' >&2
			return 1
			;;
	esac

	for service in apache nginx proxy; do
		capture_request "${service}" "${state}" "${service}" '/.well-known/oauth-authorization-server' "${metadata_status}" "${metadata_identity}" true
		capture_request "${service}" "${state}" "${service}" '/.well-known/oauth-protected-resource' "${metadata_status}" "${metadata_identity}" true
		capture_request "${service}" "${state}" "${service}" '/.well-known/oauth-protected-resource/integrations/example' "${metadata_status}" "${isolated_identity}" true
		capture_request "${service}" "${state}" "${service}" '/charter-proof/operation' "${operation_status}" "${operation_identity}" true
	done
}

run_prepared_boundary_matrix() {
	capture_request apache prepared apache '/.well-known/oauth-protected-resource/integrations/example' 200 "${P5_ISSUER}/integrations/example" true
	capture_request apache prepared apache '/.well-known/openid-configuration' 404 '' true
	capture_request apache prepared apache '/wp-json/.well-known/oauth-authorization-server' 404 '' true
	capture_request apache prepared apache '/integrations/example/.well-known/oauth-protected-resource' 404 '' true
	capture_request apache prepared apache '/.well-known/oauth-authorization-server' 200 "${P5_ISSUER}" true \
		--header 'Forwarded: host=attacker.invalid;proto=http' \
		--header 'X-Forwarded-Host: attacker.invalid' \
		--header 'X-Forwarded-Proto: http' \
		--header 'X-Forwarded-Port: 81'
	capture_request wrong-vhost prepared apache '/.well-known/oauth-authorization-server' 404 '' true \
		--header 'Host: attacker.invalid'
	capture_request wrong-port prepared apache '/.well-known/oauth-authorization-server' 404 '' true \
		--header 'Host: issuer.charter.test:8443'
	capture_request wrong-query prepared apache '/.well-known/oauth-authorization-server?tenant=one' 404 '' true
	capture_plain_http_rejection

	capture_request dot-deny prepared dot-deny '/.well-known/oauth-authorization-server' 403 '' false
	capture_request physical-well-known prepared physical-well-known '/.well-known/oauth-authorization-server' 404 '' false
	capture_request intercept-redirect prepared intercept-redirect '/.well-known/oauth-authorization-server' 302 '' false
	capture_request intercept-json prepared intercept-json '/.well-known/oauth-authorization-server' 200 "${P5_ISSUER}" false
	capture_request html-fallback prepared html-fallback '/.well-known/oauth-authorization-server' 200 '' false

	host_capture_request
}

run_cleanup_probe() {
	local apache_id

	p5_emit_failure_logs=false
	generate_certificates
	prepare_wordpress_source
	compose config --quiet
	compose up --detach --no-deps apache client >/dev/null
	p5_compose_started=true
	wait_for_service apache
	apache_id="$(container_id apache)"
	docker stop --time 1 "${apache_id}" >/dev/null

	if [[ false != "$(docker inspect --format '{{.State.Running}}' "${apache_id}")" ]]; then
		printf 'P5 cleanup probe could not interrupt the Apache lane.\n' >&2
		return 1
	fi

	printf '{"cleanup_probe":"lane_interrupted","expected_exit":79}\n'
	return 79
}

if [[ "${1:-}" == '--manual-url' ]]; then
	if [[ $# -ne 2 ]]; then
		printf 'Usage: %s --manual-url <exact-discovery-url>\n' "$0" >&2
		exit 1
	fi

	run_manual_url "$2"
	exit 0
fi

if [[ "${1:-}" == '--browser-session' ]]; then
	if [[ $# -ne 1 ]]; then
		printf 'Usage: %s --browser-session\n' "$0" >&2
		exit 1
	fi

	run_browser_session
	exit 0
fi

if [[ "${1:-}" == '--cleanup-probe' ]]; then
	if [[ $# -ne 1 ]]; then
		printf 'Usage: %s --cleanup-probe\n' "$0" >&2
		exit 1
	fi

	run_cleanup_probe
	exit $?
fi

if [[ $# -ne 0 ]]; then
	printf 'P5 runner received an unknown argument.\n' >&2
	exit 1
fi

generate_certificates
prepare_wordpress_source
compose config --quiet
compose up --detach
p5_compose_started=true

for service in apache nginx proxy dot-deny physical-well-known intercept-redirect intercept-json html-fallback; do
	wait_for_service "${service}"
done

assert_network_boundaries
run_state_matrix prepared fresh
run_prepared_boundary_matrix
run_state_matrix available fresh
run_state_matrix enabled fresh
run_state_matrix prepared reused
run_prepared_boundary_matrix
run_state_matrix available reused
run_state_matrix enabled reused

printf '{"status":"passed","fresh_process":true,"reused_process":true,"boundary_matrix_fresh":true,"boundary_matrix_reused":true,"supported_lanes":3,"blocked_lanes":5,"loopback_only":true,"client_backend_isolated":true,"sensitive_frontdoor_egress":false,"data_free_loopback_relay":true}\n'
