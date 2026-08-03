# Charter

Charter is a WordPress plugin for a secure, standards-compliant OAuth 2.1 authorization server.

This repository currently contains the installable bootstrap and release infrastructure. Version `0.1.0` does not expose OAuth endpoints, client management, token storage, or an administration interface yet.

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

## Run quality checks

Run the fast local checks:

```bash
composer check
npm run format:check
```

Run WordPress integration tests:

```bash
npm run test:integration:ci
```

Build, verify, activate, and run Plugin Check against the production artifact:

```bash
npm run build:zip
npm run artifact:verify
npm run artifact:test
```

The release artifact is written to `build/charter.zip`.

## Contribute and release

Read [CONTRIBUTING.md](CONTRIBUTING.md) for development commands, [SECURITY.md](SECURITY.md) for private vulnerability reporting, and [RELEASING.md](RELEASING.md) for the protected release process.

## License

Charter is licensed under the [GNU General Public License version 2 or later](LICENSE).
