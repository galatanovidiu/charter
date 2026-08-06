# Charter OAuth security model

Charter adds an OAuth authorization layer to WordPress without replacing WordPress authentication, users, capabilities, REST routing, or handler permission callbacks.

## Trust boundaries

Each supported WordPress site is an independent issuer. The bare origin identifies both the issuer and default protected resource. Multisite network administration orchestrates isolated site operations; it does not create network-wide credentials or authority.

Charter validates the exact issuer, request origin, resource, client, redirect URI, user, scope set, and selected REST handler. The handler's WordPress `permission_callback` remains the final business-authorization decision.

Public routes, cookies and nonces, Application Passwords, and Core REST behavior remain WordPress-owned. Charter rejects a request that combines a pre-existing WordPress identity with a Charter Bearer token to avoid ambiguous identity.

## Credential protection

Authorization codes, access tokens, refresh tokens, and generated client secrets use cryptographically random opaque values. Charter persists credential digests and password hashes, not plaintext credential values.

Authorization Code requires PKCE S256. Codes are short-lived and single-use. Access tokens expire after one hour. Refresh tokens rotate atomically; reuse closes the complete grant family. RFC 7009 revocation is non-revealing for unknown tokens and closes descendant credentials for an owned grant.

Credential digests are domain-separated by issuer and credential type. They derive from current WordPress salts unless a deployment supplies `CHARTER_SECRET_KEY`. Explicit key changes fail closed until restored or deliberately adopted. Only non-secret compatibility and generation state is stored.

## Client and consent protection

Redirect URIs are exact and immutable for a client identity. HTTP local callbacks accept only exact `localhost`, `127.0.0.1`, or `[::1]` hosts and may vary only the runtime port; the path and query remain exact. Consent prominently displays the callback hostname and warns when a CIMD client uses only local callbacks because another local process could impersonate it. Confidential clients use `client_secret_post`; public clients never authenticate with a secret.

Consent binds the user, client, exact resource, scopes, redirect, grant policy, and Client ID Metadata Document fingerprint. Material changes require new consent. Continuing access has inactivity and absolute expiration limits.

Anonymous registration and authorization are protected by source-, client-, user-, and issuer-bounded rate limits. Rate-limit keys are stored as digests.

## Client ID Metadata Document fetching

Charter treats every Client ID Metadata Document URL as untrusted outbound input. It requires HTTPS, resolves bounded DNS chains, rejects every non-global terminal address, pins the screened address set to one TLS-verified cURL connection, and disables redirects, retries, connection reuse, compression, and ambient proxy use.

Response status, headers, media type, content coding, and body size are bounded. Cache freshness is capped. A failed, malformed, stale, or changed document cannot silently authorize a client.

## Administrative protection

Site and Network Admin mutations require the relevant WordPress capability, exact operation-bound nonces, immutable issuer or site bindings, and explicit confirmation for destructive or emergency actions. Network operations execute selected sites sequentially and restore blog context.

Audit events intentionally exclude credential values, signing material, fingerprint inputs, and recoverable secrets. If an effective containment or signing-key transition persists before its audit write completes, Charter reports reconciliation as pending and prevents the state from being misreported.

## Incident containment

Issuance pause stops new registration, authorization, consent completion, code exchange, and refresh while preserving existing access-token use. Lockdown also rejects every Charter Bearer credential. RFC 7009 revocation and administrator recovery paths remain available.

Containment is reversible. Grant or client revocation is the durable response when credentials must remain unusable after resume.

## Data destruction

Deactivation retains security state. Plugin uninstall removes all Charter-owned site data. Network activation is required on Multisite so Charter is loaded during permanent site deletion and can add exact site-prefixed tables to WordPress's deletion list.

## Deliberate limits

Charter v1 does not provide Implicit, Resource Owner Password Credentials, Device Authorization, Client Credentials, JWT access tokens, token introspection, HTTP Basic client authentication, registration management credentials, cross-site tokens, or a network-wide issuer.

Deployments remain responsible for HTTPS termination, WordPress and PHP patching, secure administrator accounts, reliable cron, trusted backups, protected WordPress salts or `CHARTER_SECRET_KEY`, REST handler permission callbacks, and monitoring of Site Health and audit events.
