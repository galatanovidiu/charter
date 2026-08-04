#!/usr/bin/env bash

set -euo pipefail

project_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
label_name='org.charter.slice0.p1.run'
run_id="charter-p1-$(date -u +%Y%m%d%H%M%S)-$(openssl rand -hex 4)"
runtime_image='wordpress:cli-php8.4'
wordpress_directory='-'
database_container='-'
runtime_container='-'
network_name='-'
volume_name='-'
watchdog_pid='-'

fixed_failure() {
	printf '%s\n' '{"schema_version":1,"record_type":"harness_failure","status":"failed","passed":false}'
}

cleanup_current_lane() {
	bash "${project_root}/tools/cleanup-slice0-atomic-lifecycle.sh" \
		"${run_id}" \
		"${database_container}" \
		"${runtime_container}" \
		"${network_name}" \
		"${volume_name}" \
		'-'

	database_container='-'
	runtime_container='-'
	network_name='-'
	volume_name='-'
}

cleanup_all() {
	local exit_code=$?

	trap - EXIT INT TERM
	stop_watchdog
	cleanup_current_lane || true
	bash "${project_root}/tools/cleanup-slice0-atomic-lifecycle.sh" \
		"${run_id}" '-' '-' '-' '-' "${wordpress_directory}" || true
	exit "${exit_code}"
}

stop_watchdog() {
	local watchdog_child_pid

	if [[ "${watchdog_pid}" == '-' ]]; then
		return
	fi

	watchdog_child_pid="$(pgrep -P "${watchdog_pid}" | head -n 1 || true)"
	if [[ -n "${watchdog_child_pid}" ]]; then
		kill "${watchdog_child_pid}" >/dev/null 2>&1 || true
	fi
	kill "${watchdog_pid}" >/dev/null 2>&1 || true
	wait "${watchdog_pid}" 2>/dev/null || true
	watchdog_pid='-'
}

start_watchdog() {
	local runner_pid=$$
	local timeout="$1"

	(
		watchdog_process_pid="${BASHPID}"
		trap - EXIT INT TERM
		sleep "${timeout}"
		child_pid="$(pgrep -P "${runner_pid}" | awk -v watchdog="${watchdog_process_pid}" '$1 != watchdog { print; exit }' || true)"
		if [[ -n "${child_pid}" ]]; then
			kill -TERM "${child_pid}" >/dev/null 2>&1 || true
		fi
		kill -TERM "${runner_pid}" >/dev/null 2>&1 || true
	) &
	watchdog_pid=$!
}

trap cleanup_all EXIT
trap 'exit 124' INT TERM

workers="${CHARTER_ATOMIC_WORKERS:-8}"
rounds="${CHARTER_ATOMIC_ROUNDS:-50}"
lane_timeout="${CHARTER_ATOMIC_LANE_TIMEOUT:-3600}"
total_timeout="${CHARTER_ATOMIC_TOTAL_TIMEOUT:-7200}"

if [[ ! "${workers}" =~ ^[0-9]+$ ]] || (( workers < 8 || workers > 32 )); then
	fixed_failure
	exit 1
fi

if [[ ! "${rounds}" =~ ^[0-9]+$ ]] || (( rounds < 50 || rounds > 500 )); then
	fixed_failure
	exit 1
fi

if [[ ! "${lane_timeout}" =~ ^[0-9]+$ ]] || (( lane_timeout < 60 || lane_timeout > 7200 )); then
	fixed_failure
	exit 1
fi

if [[ ! "${total_timeout}" =~ ^[0-9]+$ ]] || (( total_timeout < 300 || total_timeout > 14400 )); then
	fixed_failure
	exit 1
fi

start_watchdog "${total_timeout}"

artifact_path="${project_root}/build/charter.zip"
if [[ ! -f "${artifact_path}" ]]; then
	fixed_failure
	exit 1
fi

artifact_sha256="$(shasum -a 256 "${artifact_path}" | awk '{print $1}')"
if [[ ! "${artifact_sha256}" =~ ^[a-f0-9]{64}$ ]]; then
	fixed_failure
	exit 1
fi

wordpress_url="$(WORDPRESS_BRANCH=6.9 WORDPRESS_PHP_VERSION=8.4 bash "${project_root}/tools/resolve-wordpress-core.sh")"
if [[ "${wordpress_url}" != 'https://downloads.w.org/release/wordpress-6.9.5.zip' ]]; then
	fixed_failure
	exit 1
fi

wordpress_directory="$(mktemp -d "${TMPDIR:-/tmp}/charter-p1-wordpress.XXXXXXXX")"
printf '%s' "${run_id}" >"${wordpress_directory}/.charter-p1-owner"
curl --fail --silent --show-error --location "${wordpress_url}" --output "${wordpress_directory}/wordpress.zip"
unzip -q "${wordpress_directory}/wordpress.zip" -d "${wordpress_directory}"
chmod 0755 "${wordpress_directory}" "${wordpress_directory}/wordpress"

php -r '$wp_version = null; require $argv[1]; exit("6.9.5" === $wp_version ? 0 : 1);' \
	"${wordpress_directory}/wordpress/wp-includes/version.php" || {
	fixed_failure
	exit 1
}

docker pull "${runtime_image}" >/dev/null

matrix=(
	'mysql|8.0.46|mysql:8.0.46|REPEATABLE READ|null'
	'mysql|8.0.46|mysql:8.0.46|READ COMMITTED|null'
	'mysql|8.4.11|mysql:8.4.11|REPEATABLE READ|null'
	'mysql|8.4.11|mysql:8.4.11|READ COMMITTED|null'
	'mariadb|10.11.18|mariadb:10.11.18|REPEATABLE READ|0'
	'mariadb|10.11.18|mariadb:10.11.18|READ COMMITTED|0'
	'mariadb|12.3.2|mariadb:12.3.2|REPEATABLE READ|1'
	'mariadb|12.3.2|mariadb:12.3.2|READ COMMITTED|1'
)

lane_number=0
for lane in "${matrix[@]}"; do
	IFS='|' read -r family version image isolation snapshot_isolation <<<"${lane}"
	lane_slug="${lane_number}-$(tr '[:upper:] ' '[:lower:]-' <<<"${isolation}" | tr -d '\n')"
	database_container="${run_id}-${lane_slug}-db"
	runtime_container="${run_id}-${lane_slug}-php"
	network_name="${run_id}-${lane_slug}-network"
	volume_name="${run_id}-${lane_slug}-data"
	database_name='charter_p1_proof'
	database_user='charter_p1_worker'
	database_password="$(openssl rand -hex 24)"
	root_password="$(openssl rand -hex 24)"

	docker pull "${image}" >/dev/null
	image_repository="${image%%:*}"
	database_digest="$(
		docker image inspect --format '{{range .RepoDigests}}{{println .}}{{end}}' "${image}" |
			awk -F '@' -v repository="${image_repository}" '$1 == repository { print $2; exit }'
	)"
	if [[ ! "${database_digest}" =~ ^sha256:[a-f0-9]{64}$ ]]; then
		fixed_failure
		exit 1
	fi

	docker network create --label "${label_name}=${run_id}" "${network_name}" >/dev/null
	docker volume create --label "${label_name}=${run_id}" "${volume_name}" >/dev/null
	docker container run --detach \
		--name "${database_container}" \
		--label "${label_name}=${run_id}" \
		--network "${network_name}" \
		--mount "type=volume,source=${volume_name},target=/var/lib/mysql" \
		--env "MYSQL_DATABASE=${database_name}" \
		--env "MYSQL_USER=${database_user}" \
		--env "MYSQL_PASSWORD=${database_password}" \
		--env "MYSQL_ROOT_PASSWORD=${root_password}" \
		"${image}" >/dev/null

	docker container run --detach \
		--name "${runtime_container}" \
		--label "${label_name}=${run_id}" \
		--network "${network_name}" \
		--mount "type=bind,source=${project_root},target=/workspace,readonly" \
		--mount "type=bind,source=${wordpress_directory}/wordpress,target=/wordpress,readonly" \
		--env "CHARTER_ATOMIC_DB_HOST=${database_container}" \
		--env 'CHARTER_ATOMIC_DB_PORT=3306' \
		--env "CHARTER_ATOMIC_DB_NAME=${database_name}" \
		--env "CHARTER_ATOMIC_DB_USER=${database_user}" \
		--env "CHARTER_ATOMIC_DB_PASSWORD=${database_password}" \
		--env "CHARTER_ATOMIC_DB_FAMILY=${family}" \
		--env "CHARTER_ATOMIC_DB_VERSION=${version}" \
		--env "CHARTER_ATOMIC_DB_IMAGE_DIGEST=${database_digest}" \
		--env "CHARTER_ATOMIC_ISOLATION=${isolation}" \
		--env "CHARTER_ATOMIC_SNAPSHOT_ISOLATION=${snapshot_isolation}" \
		--env "CHARTER_ATOMIC_ARTIFACT_SHA256=${artifact_sha256}" \
		--env 'CHARTER_ATOMIC_WORDPRESS_VERSION=6.9.5' \
		--env 'CHARTER_ATOMIC_WORDPRESS_DIR=/wordpress' \
		--env "CHARTER_ATOMIC_WORKERS=${workers}" \
		--env "CHARTER_ATOMIC_ROUNDS=${rounds}" \
		--env "CHARTER_ATOMIC_LANE_TIMEOUT=${lane_timeout}" \
		--entrypoint /bin/sh \
		"${runtime_image}" -c 'while :; do sleep 3600; done' >/dev/null

	if ! docker exec "${runtime_container}" php /workspace/tests/fixtures/atomic-lifecycle/AtomicLifecycleLaneRunner.php wait >/dev/null 2>&1; then
		fixed_failure
		exit 1
	fi

	if ! docker exec --workdir /workspace "${runtime_container}" \
		php -d display_errors=0 -d log_errors=0 \
		vendor/bin/phpunit \
		--configuration=phpunit.xml.dist \
		--bootstrap=tests/bootstrap-unit.php \
		--testsuite=slice0-atomic \
		--filter=AtomicLifecycleBehaviorTest \
		--do-not-cache-result >/dev/null 2>&1; then
		fixed_failure
		exit 1
	fi

	docker exec "${runtime_container}" \
		timeout -s TERM -k 10 "${lane_timeout}" \
		php -d display_errors=0 -d log_errors=0 \
		/workspace/tests/fixtures/atomic-lifecycle/AtomicLifecycleLaneRunner.php run

	cleanup_current_lane
	((lane_number += 1))
done

stop_watchdog
trap - EXIT INT TERM
bash "${project_root}/tools/cleanup-slice0-atomic-lifecycle.sh" \
	"${run_id}" '-' '-' '-' '-' "${wordpress_directory}"
