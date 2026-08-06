# Privacy and data retention

Charter processes OAuth security state inside the WordPress database. It does not include telemetry or send data to the plugin author.

## Data Charter stores

Each prepared site stores its own data:

- Client identifiers, names, registration source, redirect URIs, authentication method, grant policy, status, and activity times.
- One-way password hashes for confidential-client secrets.
- User identifiers, exact issuer and resource identifiers, scopes, authorization state, activity times, and terminal revocation reasons.
- One-way digests and lifecycle metadata for authorization transactions, codes, access tokens, and refresh-token families.
- Rate-limit bucket digests, counters, and expiry times.
- Security audit events with issuer, event type, actor or represented user identifiers where applicable, client, resource, scopes, outcome, reason, time, and bounded source address where applicable.
- Validated Client ID Metadata Document projections and freshness times.
- Site lifecycle, cleanup, containment, Dynamic Client Registration, and non-secret signing-key compatibility state.
- A per-user cursor used to group revocation notices.

Charter does not persist plaintext access tokens, refresh tokens, authorization codes, confidential-client secrets, WordPress salts, or `CHARTER_SECRET_KEY`.

## Data sent outside WordPress

When a user starts authorization for an unknown HTTPS URL client ID, Charter may resolve DNS and fetch that exact Client ID Metadata Document. The request discloses the WordPress server's source address and ordinary TLS/HTTP connection metadata to the client ID host.

Charter does not follow redirects, use ambient proxy settings, send WordPress cookies or credentials, or fetch private and non-global destinations. Rejected, malformed, stale, or oversized responses do not become authorization authority.

OAuth clients receive only data exposed by the protected REST handlers they call after both scope validation and the handler's WordPress permission callback succeed.

## Retention periods

Daily issuer-local cleanup applies these limits:

- Authorization transactions and terminal short credentials: 24 hours.
- Refresh-token lineage after the complete family closes: 30 days.
- Dynamic clients that were never authorized: 7 days.
- Inactive authorized dynamic clients with no active grants: 90 days.
- Terminal grant history and audit events: 90 days.

Active grants, active client registrations, and credentials required for current authorization remain until they expire, are revoked, become inactive under the rules above, or are removed with the site or plugin.

## User controls

Users can inspect and disconnect active authorizations under **Profile > Connected Apps**. Password changes, account deletion, and Multisite site-access removal close affected grants. Administrators can revoke one authorization or all active authorizations for a site, and can block or delete a client.

Charter does not currently register separate WordPress personal-data exporter or eraser callbacks. Its OAuth-specific controls provide access and revocation, while WordPress user deletion and Multisite access-removal hooks close authorizations. Site owners should include Charter's stored categories, outbound Client ID Metadata Document requests, retention periods, and administrator access in their privacy notice and data-request procedures.

## Deactivation, site deletion, and uninstall

Deactivation retains all Charter data.

On network-active Multisite, permanent site deletion removes that site's Charter tables and user-notice cursors without touching sibling issuers.

Deleting the plugin runs `uninstall.php` and permanently removes Charter tables, options, scheduled cleanup events, and user-notice cursors. Multisite uninstall visits every site sequentially. Back up required records before deletion; Charter has no recovery path after uninstall.
