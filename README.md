# Charter

Charter is a WordPress OAuth 2.1 authorization server with site-local issuers, exact protected-resource boundaries, and WordPress-native administration.

Charter publishes RFC 8414 and RFC 9728 metadata and supports Authorization Code with mandatory PKCE S256, opaque one-hour access tokens, rotating refresh tokens with replay containment, RFC 7009 revocation, RFC 7591 Dynamic Client Registration, and HTTPS Client ID Metadata Documents. Integrations can protect exact WordPress REST handlers and register narrower resources and scopes without replacing the handler's WordPress permission callback.

Users approve first use and material changes, inspect active authorizations under **Profile > Connected Apps**, and disconnect complete grants. Site and network administrators can govern clients and grants, pause issuance, lock down Bearer access, monitor bounded retention, and manage explicit signing-key replacements without exposing credential material.

## Platform requirements

- WordPress 6.9 or later
- PHP 8.4 or later
- Node.js 24 for local WordPress environments and release tooling
- Composer 2
- Docker for WordPress integration and artifact activation tests

The distributed plugin has no Composer runtime dependencies and does not ship a `vendor/` directory.

## Install the development build

1. Install PHP and Node.js dependencies:

    ```bash
    composer install
    npm ci
    ```

2. Start the local WordPress environment:

    ```bash
    npm run env:start
    ```

3. Open the URL reported by `wp-env`.

4. In WordPress, open **Settings > Charter OAuth**.

    Charter starts in the **Prepared** state for a supported single-site activation. Verify both exact metadata URLs shown on the page, select the verification checkbox, and click **Enable OAuth**.

    Prepared metadata identifies the canonical issuer and resource without advertising disabled grants or endpoints. The operational capability fields appear after OAuth is enabled.

5. Under **Pre-register a client**, enter its client ID, display name, exact redirect URI, public or confidential type, and continuing-access policy. Native loopback clients may use an HTTP URI on literal `127.0.0.1` or `[::1]`; only the runtime port may vary.

    A confidential-client secret is displayed once in a no-store response. Save it immediately: Charter persists only its password hash and cannot retrieve the original value later. Confidential clients send the secret as `client_secret` in the form-encoded token or revocation request; HTTP Basic authentication is not supported.

Charter uses the canonical bare origin as both the issuer identifier and the default protected-resource identifier. HTTP issuer URLs work only in an explicit local WordPress environment or when `CHARTER_DEVELOPMENT_MODE` is `true`; non-loopback development hosts also require an exact entry in the `CHARTER_DEVELOPMENT_HOSTS` array constant.

On Multisite, network-activate Charter, then prepare and enable each site under **Network Settings > Charter OAuth**. Per-site activation is unsupported and does not initialize OAuth storage.

## Protect a REST handler

Wrap the exact handler you pass to `register_rest_route()`:

```php
use GalatanOvidiu\Charter\Rest\ProtectedRoute;

register_rest_route(
    'example/v1',
    '/records',
    ProtectedRoute::assign(
        array(
            'methods'             => 'GET',
            'permission_callback' => static fn (): bool => current_user_can( 'read' ),
            'callback'            => 'example_get_records',
        )
    )
);
```

The default assignment requires the `wordpress:access` scope for the site's canonical resource. Charter establishes the represented WordPress user before the existing `permission_callback` runs and restores the prior request identity afterward. Public handlers and requests authenticated with cookies/nonces or Application Passwords continue through WordPress without Bearer validation. A request that combines an existing WordPress identity with a Charter Bearer credential is rejected.

## Run quality checks

Run the fast local checks:

```bash
composer check
npm run format:check
npm run test:javascript
```

Run WordPress integration tests:

```bash
npm run test:integration:ci
```

Run the focused real-HTTP lifecycle through WordPress login, consent, public and confidential code exchange, concurrent refresh replay, grant closure, RFC 7009 revocation, and protected REST requests:

```bash
npm run test:oauth:http:ci
```

Build, verify, activate, and run Plugin Check against the production artifact:

```bash
npm run build:zip
npm run artifact:verify
npm run artifact:test
npm run secret:check
```

The release artifact is written to `build/charter.zip`.

## Read the product guides

- [Operator guide](docs/operator-guide.md): installation, upgrades, Multisite, cron, incident controls, signing keys, backups, and removal.
- [Administrator guide](docs/administrator-guide.md): issuer enablement, client policy, grant governance, containment, and Network Admin.
- [User guide](docs/user-guide.md): consent, current access, and disconnection.
- [Integrator guide](docs/integrator-guide.md): discovery, clients, flows, REST protection, resources, and scopes.
- [Privacy and retention](docs/privacy.md): stored data, outbound metadata requests, retention, and deletion.
- [Security model](docs/security-model.md): trust boundaries, credential handling, SSRF controls, administration, and deliberate limits.

## Contribute and release

Read [CONTRIBUTING.md](CONTRIBUTING.md) for development commands, [SECURITY.md](SECURITY.md) for private vulnerability reporting, and [RELEASING.md](RELEASING.md) for the protected release process.

## License

Charter is licensed under the [GNU General Public License version 2 or later](LICENSE).
