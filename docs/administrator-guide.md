# Administer a Charter OAuth issuer

This guide covers the controls available to site administrators and Multisite network administrators.

## Prepare and enable a site

On a single site, activation installs the site-local schema and prepares a supported canonical issuer. On Multisite, a network administrator selects and prepares each site under **Network Settings > Charter OAuth**.

1. Open **Settings > Charter OAuth**.
2. Confirm that the issuer and default resource are the intended bare origin.
3. Open both metadata links from the environment where clients will discover the site.
4. Confirm the verification checkbox.
5. Click **Enable OAuth**.

Prepared sites publish identity-only metadata. Operational endpoints and grant capabilities appear after enablement.

## Choose how clients register

Dynamic Client Registration is enabled by default. Under **Dynamic Client Registration**, clear **Accept new dynamic registrations** to stop new registrations. Existing client identities and grants remain intact.

Use **Pre-register a client** when you need an administrator-owned client record. Every client uses Authorization Code with PKCE S256.

- Choose **Public (no secret)** for native and other clients that cannot keep a secret. Browser products must keep OAuth credential handling in a backend-for-frontend; Charter v1 does not support browser-only JavaScript clients.
- Choose **Confidential (client secret)** only when the client can protect a server-side secret.
- Select continuing access only when the client needs rotating refresh tokens after user consent.

Charter displays a confidential-client secret once and stores only its password hash. Transfer it through an approved secret channel. If the secret is lost, create a new client identity.

Block or delete a client to close its active grants and descendant credentials. Deleting a client is terminal. Neither action reveals stored secrets.

## Review and revoke authorizations

The **Site authorizations** section groups active grants by user. It shows the application, exact resource, scopes, continuing-access choice, authorization time, and last activity.

You may revoke one grant or use the separately confirmed **Revoke all OAuth grants** action. Revocation closes every descendant code, access token, and refresh-token family for the selected grant. Client registrations remain available for later authorization unless they are separately blocked or deleted.

Review **Recent OAuth security events** after governance or incident actions. The audit ledger stores identifiers and outcomes, not credential values or root key material.

## Use emergency containment

An enabled issuer has three modes:

- **Resumed** permits normal OAuth operation.
- **Issuance paused** rejects new registration, authorization, consent completion, code exchange, and refresh. Existing access tokens remain usable.
- **Lockdown** includes the issuance pause and rejects every Charter Bearer credential.

Every transition requires capability, a request-bound nonce, and explicit confirmation. The UI reports when the effective mode changed but the corresponding audit event still needs reconciliation.

Containment is reversible and separate from **Revoke all OAuth grants**. Use revocation when credentials must remain invalid after service resumes.

## Handle a signing-key warning

Charter reports signing-key source and compatibility without exposing key material.

- WordPress-derived material changes retire existing credentials automatically and do not require adoption.
- An unavailable or invalid explicit `CHARTER_SECRET_KEY` blocks OAuth credential operations until configuration is corrected.
- A valid but changed explicit key produces a site-local mismatch. Restore the accepted key or explicitly adopt the replacement.

Adopting a replacement invalidates every earlier explicit-key generation while preserving registrations, grants, containment state, rates, and audit history.

## Administer Multisite safely

Charter has no network-wide OAuth issuer, client, grant, or credential. **Network Settings > Charter OAuth** orchestrates one selected site at a time and restores the original blog context after each operation.

Network administrators can prepare and enable a site, inspect issuer-local state, revoke grants, change containment, and adopt signing-key replacements. Selected and all-site WP-CLI modes execute sites sequentially. Available sites are skipped by operations that require an enabled issuer.

Do not per-site activate Charter on Multisite. Network activation is required so permanent site deletion can load Charter and remove that site's custom tables.
