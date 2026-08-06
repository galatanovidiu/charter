#!/usr/bin/env bash

set -euo pipefail

project_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
artifact_config="${project_root}/build/.wp-env.artifact.json"

cd "${project_root}"

if [[ ! -f build/charter.zip ]]; then
	echo "build/charter.zip does not exist. Run npm run build:zip first." >&2
	exit 1
fi

expected_version="${EXPECTED_VERSION:-$(node --print "require('./package.json').version")}"

if [[ ! "${expected_version}" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
	echo "The expected artifact version must be a bare semantic version." >&2
	exit 1
fi

mkdir -p build

cat >"${artifact_config}" <<'JSON'
{
	"$schema": "https://schemas.wp.org/trunk/wp-env.json",
	"core": null,
	"phpVersion": "8.4",
	"testsEnvironment": false,
	"config": {
		"FS_METHOD": "direct",
		"WP_DEBUG": true,
		"WP_DEBUG_LOG": true,
		"WP_DEVELOPMENT_MODE": "plugin"
	},
	"mappings": {
		"wp-content/uploads/charter-artifacts": "./build"
	}
}
JSON

cleanup() {
	local exit_code=$?

	if (( exit_code != 0 )); then
		wp-env logs --config="${artifact_config}" --no-watch || true
	fi

	wp-env destroy --config="${artifact_config}" --force || true
	exit "${exit_code}"
}

trap cleanup EXIT INT TERM

wp-env destroy --config="${artifact_config}" --force >/dev/null 2>&1 || true
wp-env start --config="${artifact_config}" --auto-port
wp-env run cli --config="${artifact_config}" wp plugin install \
	/var/www/html/wp-content/uploads/charter-artifacts/charter.zip \
	--activate \
	--force
wp-env run cli --config="${artifact_config}" wp plugin is-active charter
wp-env run cli --config="${artifact_config}" env EXPECTED_VERSION="${expected_version}" wp eval '
	$expected_version = getenv( "EXPECTED_VERSION" );

	if (
		! is_string( $expected_version )
		|| ! defined( "CHARTER_VERSION" )
		|| $expected_version !== CHARTER_VERSION
	) {
		throw new RuntimeException( "The activated artifact version is incorrect." );
	}
'
wp-env run cli --config="${artifact_config}" wp eval '
	$site_id = get_current_blog_id();
	$tables  = GalatanOvidiu\Charter\Schema::tablesForSite( $site_id );
	global $wpdb;
	foreach ( $tables as $table ) {
		if ( $table !== $wpdb->get_var( $wpdb->prepare( "SHOW TABLES LIKE %s", $wpdb->esc_like( $table ) ) ) ) {
			throw new RuntimeException( "The activated artifact did not install every Charter table." );
		}
	}
	update_option( "charter_oauth_dcr_enabled", "0", false );
	update_option( "charter_oauth_emergency_mode", array( "mode" => "lockdown" ), false );
	update_user_option( 1, "charter_oauth_revocation_notice_cursor", array( "grant_id" => 1 ) );
	wp_schedule_event( time() + HOUR_IN_SECONDS, "daily", "charter_oauth_daily_cleanup", array( "daily" ), true );
	$rules = get_option( "rewrite_rules", array() );
	foreach (
		array(
			"^\\.well-known/oauth-authorization-server/?$",
			"^\\.well-known/oauth-protected-resource/?$",
			"^\\.well-known/oauth-protected-resource/(.+)$",
		) as $rule
	) {
		if ( ! isset( $rules[ $rule ] ) ) {
			throw new RuntimeException( "The activated artifact did not persist every Charter rewrite rule." );
		}
	}
'
wp-env run cli --config="${artifact_config}" wp plugin deactivate charter
if wp-env run cli --config="${artifact_config}" wp plugin is-active charter; then
	echo 'Artifact deactivation left Charter active.' >&2
	exit 1
fi
wp-env run cli --config="${artifact_config}" wp eval '
	global $wpdb;
	$prefix = $wpdb->get_blog_prefix();
	foreach ( array( "credentials", "grants", "clients", "rate_limits", "audit", "cimd_cache" ) as $suffix ) {
		$table = $prefix . "charter_oauth_" . $suffix;
		if ( $table !== $wpdb->get_var( $wpdb->prepare( "SHOW TABLES LIKE %s", $wpdb->esc_like( $table ) ) ) ) {
			throw new RuntimeException( "Deactivation removed a Charter table." );
		}
	}
	if ( "0" !== get_option( "charter_oauth_dcr_enabled" ) || false === get_option( "charter_oauth_site_state", false ) ) {
		throw new RuntimeException( "Deactivation removed Charter state." );
	}
'
wp-env run cli --config="${artifact_config}" wp plugin install \
	/var/www/html/wp-content/uploads/charter-artifacts/charter.zip \
	--force
wp-env run cli --config="${artifact_config}" wp plugin activate charter
wp-env run cli --config="${artifact_config}" wp plugin is-active charter
wp-env run cli --config="${artifact_config}" env EXPECTED_VERSION="${expected_version}" wp eval '
	$expected_version = getenv( "EXPECTED_VERSION" );
	if ( ! is_string( $expected_version ) || $expected_version !== CHARTER_VERSION ) {
		throw new RuntimeException( "The upgraded artifact version is incorrect." );
	}
	if ( "0" !== get_option( "charter_oauth_dcr_enabled" ) || false === get_option( "charter_oauth_site_state", false ) ) {
		throw new RuntimeException( "Artifact upgrade did not preserve Charter state." );
	}
'
wp-env run cli --config="${artifact_config}" wp plugin install plugin-check --activate
wp-env run cli --config="${artifact_config}" wp plugin check charter \
	--require=/var/www/html/wp-content/plugins/plugin-check/cli.php \
	--format=strict-table \
	--slug=charter
wp-env run cli --config="${artifact_config}" wp plugin uninstall charter --deactivate
wp-env run cli --config="${artifact_config}" wp eval '
	global $wpdb;
	$prefix = $wpdb->get_blog_prefix();
	foreach ( array( "credentials", "grants", "clients", "rate_limits", "audit", "cimd_cache" ) as $suffix ) {
		$table = $prefix . "charter_oauth_" . $suffix;
		if ( $table === $wpdb->get_var( $wpdb->prepare( "SHOW TABLES LIKE %s", $wpdb->esc_like( $table ) ) ) ) {
			throw new RuntimeException( "Plugin uninstall retained a Charter table." );
		}
	}
	foreach (
		array(
			"charter_oauth_schema_version",
			"charter_oauth_site_state",
			"charter_oauth_clients",
			"charter_oauth_clients_migrated",
			"charter_oauth_dcr_enabled",
			"charter_oauth_emergency_mode",
			"charter_oauth_cleanup_status",
			"charter_oauth_cleanup_first_scheduled_at",
			"charter_oauth_last_cleanup_at",
			"charter_oauth_signing_key_guard",
		) as $option
	) {
		if ( false !== get_option( $option, false ) ) {
			throw new RuntimeException( "Plugin uninstall retained a Charter option." );
		}
	}
	$meta_key = $prefix . "charter_oauth_revocation_notice_cursor";
	if ( 0 !== (int) $wpdb->get_var( $wpdb->prepare( "SELECT COUNT(*) FROM {$wpdb->usermeta} WHERE meta_key = %s", $meta_key ) ) ) {
		throw new RuntimeException( "Plugin uninstall retained Charter user metadata." );
	}
	if ( false !== wp_next_scheduled( "charter_oauth_daily_cleanup" ) ) {
		throw new RuntimeException( "Plugin uninstall retained Charter cron events." );
	}
	$rules = get_option( "rewrite_rules", array() );
	foreach ( $rules as $target ) {
		if ( is_string( $target ) && str_contains( $target, "/charter/v1/metadata/" ) ) {
			throw new RuntimeException( "Plugin uninstall retained a Charter rewrite rule." );
		}
	}
'
if wp-env run cli --config="${artifact_config}" wp plugin is-installed charter; then
	echo 'Plugin uninstall retained the Charter plugin directory.' >&2
	exit 1
fi

trap - EXIT INT TERM
wp-env destroy --config="${artifact_config}" --force
