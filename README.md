# Charter

**OAuth 2.1 for WordPress, built for MCP.**

Charter turns a WordPress site into a standards-based OAuth 2.1 authorization server. MCP servers and other WordPress REST integrations can use it to give clients scoped, revocable access without replacing WordPress users, roles, capabilities, or permission checks.

Instead of asking people to share long-lived WordPress credentials with every application, Charter gives each client its own authorization flow. The user signs in to WordPress, reviews the requested access, and can disconnect the application later.

## Built for MCP, useful beyond it

Charter is a general OAuth server, not an MCP server or tool catalog. It provides the authorization layer that an MCP server needs while leaving tools, resources, and business operations to the integrating plugin.

Its MCP-focused compatibility includes:

- OAuth authorization-server and protected-resource discovery.
- Authorization Code with mandatory PKCE S256.
- Resource-bound access and scope challenges.
- Public desktop and command-line clients with runtime localhost callbacks.
- Dynamic Client Registration and HTTPS Client ID Metadata Documents.
- Compatibility with Claude Code's client metadata and local callback flow.
- Rotating refresh tokens for approved continuing access.

An MCP integration can protect its WordPress REST endpoints with Charter and define its own resource and scopes. Charter authenticates the represented WordPress user; the integration's existing WordPress permission checks and any tool-level safeguards still decide what that user may do.

## Why Charter

- **Standards-based access.** Clients discover the issuer and protected resources through standard OAuth metadata instead of hard-coded endpoint conventions.
- **WordPress-native authorization.** OAuth adds a new authentication path without weakening or replacing WordPress permission checks.
- **Clear user control.** Users approve access, see connected applications under **Profile > Connected Apps**, and revoke complete grants.
- **Safer credentials.** Access tokens are opaque, short-lived, and resource-bound. Refresh tokens rotate, and replay closes the affected credential family.
- **Operational control.** Administrators can govern clients and grants, pause new issuance, lock down Bearer access during an incident, and inspect security health without exposing credential material.
- **Site-local isolation.** Every site has its own issuer and OAuth state. Multisite installations remain isolated per site under Network Admin control.

## How it works

1. A WordPress integration protects one or more REST handlers and declares the OAuth resource and scopes it needs.
2. The client discovers Charter's OAuth metadata and starts an Authorization Code flow with PKCE.
3. WordPress authenticates the user and Charter shows the requested application, resource, and permissions.
4. After approval, Charter issues credentials bound to that client, user, resource, and scope set.
5. On every protected request, Charter establishes the WordPress user before the integration's existing permission callback runs.

Public REST routes and existing cookie, nonce, and Application Password authentication continue to work normally. Requests cannot combine an existing WordPress identity with a Charter Bearer credential.

## Supported clients

Charter supports public and confidential OAuth clients:

- Desktop, command-line, and MCP clients can use PKCE and exact localhost callbacks.
- Hosted applications can use confidential clients with exact HTTPS callbacks.
- Clients may be registered by an administrator, through Dynamic Client Registration, or through an HTTPS Client ID Metadata Document.

Charter implements OAuth authorization, not OpenID Connect. It does not issue ID Tokens or act as a general-purpose single sign-on provider.

## Get started

1. Download `charter.zip` from the [GitHub Releases page](https://github.com/galatanovidiu/charter/releases).
2. Install and activate it through **Plugins > Add New Plugin**. On Multisite, network-activate Charter.
3. Open **Settings > Charter OAuth**. On Multisite, use **Network Settings > Charter OAuth** to select a site.
4. Verify the displayed authorization-server and protected-resource metadata URLs, then enable the issuer.
5. Register a client or install an integration that connects its protected REST routes to Charter.

Charter requires WordPress 6.9 or later, PHP 8.4 or later, and an HTTPS site with a bare-origin public URL. HTTP is supported only for explicit local development. Multisite installations require network activation.

## Security by design

Charter uses exact redirect and resource matching, mandatory PKCE, one-time authorization codes, rotating refresh tokens, replay containment, bounded abuse controls, secure client-metadata fetching, and explicit revocation. It adds no telemetry.

Deactivation keeps OAuth state so the plugin can be restored safely. Deleting Charter permanently removes its tables, configuration, grants, credentials, audit history, and scheduled cleanup state from every affected site.

For the complete threat model and operational boundaries, read the [security model](docs/security-model.md) and [privacy and retention guide](docs/privacy.md). Security issues should be reported privately as described in [SECURITY.md](SECURITY.md).

## Documentation

- [Operator guide](docs/operator-guide.md) — installation, upgrades, Multisite, health monitoring, incident controls, backups, and removal.
- [Administrator guide](docs/administrator-guide.md) — issuer setup, client policy, grant governance, and Network Admin.
- [User guide](docs/user-guide.md) — consent, connected applications, and revocation.
- [Integrator guide](docs/integrator-guide.md) — OAuth discovery, client profiles, REST protection, resources, and scopes.

## Contributing

Charter is open source. Bug reports, suggestions, and pull requests are welcome. See [CONTRIBUTING.md](CONTRIBUTING.md) for project guidance.

## License

Charter is licensed under the [GNU General Public License version 2 or later](LICENSE).
