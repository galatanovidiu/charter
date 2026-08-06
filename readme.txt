=== Charter – OAuth 2.1 Authorization Server ===
Contributors: galatanovidiu
Tags: oauth, authentication, security, rest-api
Requires at least: 6.9
Tested up to: 7.0
Requires PHP: 8.4
Stable tag: 0.1.0
License: GPL-2.0-or-later
License URI: https://www.gnu.org/licenses/gpl-2.0.html

Provides a secure, standards-compliant OAuth 2.1 authorization server for WordPress.

== Description ==

Charter is being built to provide OAuth 2.1 authorization-server capabilities for WordPress.

This development release provides a working pre-registered client and grant lifecycle: RFC 8414 and RFC 9728 metadata, Authorization Code with mandatory PKCE S256, public and confidential clients, short-lived single-use codes, opaque one-hour access tokens, rotating refresh tokens with replay-family protection, RFC 7009 grant-wide revocation, reusable exact consent, and exact-handler protection for WordPress REST routes.

Charter adds OAuth without replacing public routes, cookie and nonce authentication, Application Passwords, or existing WordPress permission callbacks. Users can inspect and disconnect their authorizations under Profile > Connected Apps. CIMD, Dynamic Client Registration, specialized scopes, and the remaining operational controls are still under development.

== Installation ==

1. Upload the `charter` directory to `/wp-content/plugins/`.
2. Activate Charter through the Plugins screen in WordPress.
3. Open Settings > Charter OAuth.
4. Verify the two exact metadata URLs shown for the canonical site origin, then enable OAuth.
5. Pre-register a public or confidential client with its exact redirect URI and continuing-access policy. Save a confidential-client secret when it is shown; it cannot be retrieved later.

Prepared metadata identifies the canonical issuer and resource without advertising disabled grants or endpoints. Operational capability fields appear after OAuth is enabled.

== Frequently Asked Questions ==

= Which OAuth flows are available in this development build? =

The current build supports Authorization Code for pre-registered public and confidential clients with mandatory PKCE S256. Approved continuing access uses rotating refresh tokens, and clients or users can revoke the complete grant. CIMD and Dynamic Client Registration are not implemented yet.

= How does a confidential client authenticate? =

Charter displays a generated client secret once and stores only its password hash. The client sends that secret using client_secret_post. HTTP Basic and other client-authentication methods are not supported.

= Does Charter replace WordPress authentication or permissions? =

No. Public REST routes remain public. Cookie and nonce authentication and Application Passwords remain available. The matched REST route's permission callback still decides whether the represented WordPress user may perform the operation.

== Changelog ==

= 0.1.0 =

* Added public and confidential pre-registration, Authorization Code with PKCE S256, opaque access tokens, rotating refresh tokens, replay containment, RFC 7009 revocation, exact consent reuse, personal Connected Apps controls, deterministic user-security revocation, discovery metadata, and exact-handler REST protection.
