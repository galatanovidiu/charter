=== Charter – OAuth 2.1 Authorization Server ===
Contributors: galatanovidiu
Tags: oauth, authentication, security, rest-api
Requires at least: 6.9
Tested up to: 7.1
Requires PHP: 8.4
Stable tag: 0.1.0
License: GPL-2.0-or-later
License URI: https://www.gnu.org/licenses/gpl-2.0.html

Provides a secure, standards-compliant OAuth 2.1 authorization server for WordPress.

== Description ==

Charter provides a site-local OAuth 2.1 authorization server for WordPress.

It publishes RFC 8414 and RFC 9728 metadata and supports Authorization Code with mandatory PKCE S256, public and confidential clients, opaque one-hour access tokens, rotating refresh tokens with replay containment, RFC 7009 revocation, RFC 7591 Dynamic Client Registration, and HTTPS Client ID Metadata Documents.

Charter adds OAuth without replacing public routes, cookie and nonce authentication, Application Passwords, or existing WordPress permission callbacks. Integrations can protect exact REST handlers and register narrower resources and scopes. Users inspect and disconnect their authorizations under Profile > Connected Apps. Administrators govern clients and grants, pause issuance, lock down Bearer access, monitor retention, and manage explicit signing-key replacement without exposing key material.

Every Multisite issuer remains site-local. Charter requires network activation, then a network administrator prepares and enables each selected site.

== Installation ==

1. Upload the `charter` directory to `/wp-content/plugins/`.
2. Activate Charter through the Plugins screen. On Multisite, network-activate Charter.
3. Open Settings > Charter OAuth.
4. On Multisite, prepare the selected site under Network Settings > Charter OAuth.
5. Verify the two exact metadata URLs shown for the canonical site origin, then enable OAuth.
6. Pre-register a public or confidential client with its exact redirect URI and continuing-access policy. Save a confidential-client secret when it is shown; it cannot be retrieved later.

Prepared metadata identifies the canonical issuer and resource without advertising disabled grants or endpoints. Operational capability fields appear after OAuth is enabled.

== Frequently Asked Questions ==

= Which OAuth flows are available? =

Charter supports Authorization Code for public and confidential clients with mandatory PKCE S256. Approved continuing access uses rotating refresh tokens, and clients or users can revoke the complete grant. Clients may be pre-registered, dynamically registered, or represented by an HTTPS Client ID Metadata Document.

= How does a confidential client authenticate? =

Charter displays a generated client secret once and stores only its password hash. The client sends that secret using client_secret_post. HTTP Basic and other client-authentication methods are not supported.

= Does Charter replace WordPress authentication or permissions? =

No. Public REST routes remain public. Cookie and nonce authentication and Application Passwords remain available. The matched REST route's permission callback still decides whether the represented WordPress user may perform the operation.

= What happens when I deactivate or delete Charter? =

Deactivation retains all Charter data. Deleting the plugin permanently removes Charter tables, options, scheduled cleanup events, and user-notice cursors. On Multisite, uninstall visits every site. Back up any records you must retain before deletion.

= What data leaves my WordPress site? =

Charter does not include telemetry. When a user authorizes an unknown HTTPS URL client ID, Charter may fetch that exact Client ID Metadata Document after DNS, address, TLS, redirect, media, size, and caching checks. The remote host receives ordinary connection metadata, including the WordPress server's source address.

= How long is OAuth data retained? =

Authorization transactions and terminal short credentials are retained for 24 hours, closed refresh lineage for 30 days, never-authorized dynamic clients for 7 days, inactive authorized dynamic clients without active grants for 90 days, and terminal grant and audit history for 90 days. Active security state remains until expiry, revocation, inactivity cleanup, site deletion, or plugin uninstall.

== Changelog ==

= 0.1.0 =

* Added a complete site-local OAuth 2.1 authorization server with discovery, public and confidential clients, Dynamic Client Registration, Client ID Metadata Documents, PKCE, rotating refresh tokens, replay containment, revocation, consent and Connected Apps controls, exact-handler REST protection, specialized resources and scopes, administration, retention, containment, signing-key lifecycle, Multisite isolation, and permanent uninstall cleanup.
