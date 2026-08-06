# Operate Charter OAuth

This guide covers installation, upgrades, health monitoring, incident controls, and removal. Site configuration is covered in the [administrator guide](administrator-guide.md).

## Meet the platform requirements

Run Charter on WordPress 6.9 or later and PHP 8.4 or later. The distributed plugin has no Composer runtime dependencies.

Use an HTTPS WordPress site whose Home URL and Site URL resolve to the same bare origin. HTTP issuers are accepted only in an explicit local WordPress environment.

## Install or upgrade Charter

1. Back up the WordPress database.
2. Install `charter.zip` through **Plugins > Add New Plugin** or your normal managed-plugin process.
3. Activate Charter.
4. Open **Settings > Charter OAuth** and confirm that the expected site state and issuer are shown.
5. Check **Tools > Site Health** for Charter cleanup or signing-key warnings.

Upgrading the plugin preserves site state, client registrations, grants, audit history, and credentials. Deactivation also preserves all Charter data.

> **Warning:** Deleting Charter from the Plugins screen runs `uninstall.php` and permanently removes every Charter table, option, scheduled cleanup event, and user-notice cursor. On Multisite, uninstall removes Charter data from every site.

## Activate Charter on Multisite

Charter OAuth v1 requires network activation on WordPress Multisite.

1. In **Network Admin > Plugins**, network-activate Charter.
2. Open **Network Settings > Charter OAuth**.
3. Select one site and prepare it.
4. Verify that site's exact metadata URLs from the intended client environment.
5. Enable the site issuer.

Network activation does not create a network-wide issuer or initialize every site. Each prepared site owns independent tables, options, clients, grants, credentials, audit events, cleanup state, and signing-key state. Per-site activation is unsupported and does not initialize OAuth storage.

When a site is permanently deleted, Charter adds that site's six exact custom tables to WordPress's deletion list and removes the site's user-notice cursors. This cleanup depends on Charter remaining network-active during site deletion.

## Keep scheduled cleanup healthy

Charter schedules one daily cleanup event for each prepared site. Cleanup removes bounded batches and schedules bounded continuations when eligible records remain. Credential expiry is enforced during requests even if cleanup is late.

Inspect the current site:

```bash
wp charter oauth cleanup --status
```

Run bounded cleanup for the current site:

```bash
wp charter oauth cleanup --batch-size=100 --max-batches=10
```

Inspect selected sites on a network-active installation:

```bash
wp charter oauth cleanup --network --sites=2,7 --status
```

Confirm that WordPress cron is invoked reliably. Charter reports cleanup as overdue after two days without a successful issuer-local batch.

## Respond to an OAuth incident

Inspect containment without changing state:

```bash
wp charter oauth containment --status
```

Pause new issuance while leaving existing access tokens usable:

```bash
wp charter oauth containment --mode=pause --confirm
```

Reject all Charter Bearer credentials and stop new issuance:

```bash
wp charter oauth containment --mode=lockdown --confirm
```

Resume normal operation:

```bash
wp charter oauth containment --mode=resume --confirm
```

Containment does not disable public routes, cookie and nonce authentication, Application Passwords, WordPress permission callbacks, or RFC 7009 revocation. Use **Settings > Charter OAuth** or the network-aware command options to operate on a selected site.

## Manage credential root material

By default, Charter derives credential digests from current WordPress salts. A WordPress salt change retires credentials created under the prior material, while new issuance continues.

You may instead define `CHARTER_SECRET_KEY` in trusted deployment configuration. Do not store it in the plugin directory, database, source control, logs, backups exposed to application users, or support messages. Charter stores only a site-bound, non-secret compatibility guard for an explicit key.

Inspect secret-free status:

```bash
wp charter oauth signing-key --status
```

If an intentional explicit-key replacement is reported as a mismatch, review the affected issuer and adopt the current replacement explicitly:

```bash
wp charter oauth signing-key --adopt --confirm
```

Adoption permanently retires credentials from earlier explicit-key generations. Restoring an older key does not reactivate them.

## Back up and restore

Treat Charter's site-prefixed custom tables and `charter_oauth_*` options as one issuer-local security state. Restore them consistently with the corresponding WordPress users, site URL, and WordPress salts or explicit `CHARTER_SECRET_KEY` configuration.

After a restore:

1. Confirm the canonical issuer under **Settings > Charter OAuth**.
2. Inspect signing-key status.
3. Inspect cleanup and containment status.
4. Exercise metadata, authorization, token exchange, revocation, and one protected REST route before reopening integrations.

## Remove Charter

Choose the action that matches your intent:

- Deactivate Charter to stop loading plugin code while retaining all data for later reactivation.
- Delete Charter to permanently remove its plugin files and all Charter-owned data.
- Permanently delete a Multisite site to remove that site's WordPress data and site-local Charter data while retaining sibling issuers.

There is no built-in export or recovery path for deleted Charter credentials.
