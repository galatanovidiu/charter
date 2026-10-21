# Contributing to Charter

## Prepare your environment

Charter requires PHP 8.4 or later, Composer 2, Node.js 24.18 or later in the Node.js 24 release line, npm 11.16 or later, and Docker.

Install the locked dependencies:

```bash
composer install
npm ci
```

## Run fast checks

Run all PHP quality checks and pure unit tests:

```bash
composer check
```

Check repository formatting:

```bash
npm run audit
npm run format:check
npm run test:javascript
```

The Composer check validates locked metadata and advisories, runs the complete PHPCS standard, performs static analysis, and runs pure unit tests.

Apply PHP and repository formatting:

```bash
composer format
npm run format
```

## Run WordPress tests

The integration command owns the isolated wp-env lifecycle and prints logs when a test fails:

```bash
npm run test:integration:ci
```

You can also control the environment manually:

```bash
npm run test:integration:start
npm run test:integration
npm run test:integration:stop
```

Run the disposable WordPress 6.9 Multisite environment used by the Slice 0 isolation proof:

```bash
npm run test:slice0:multisite:ci
```

This command resolves the latest WordPress 6.9 patch, runs the Multisite integration suite, prints finite logs on failure, and destroys the environment.

Run the shipped behavior boundaries before release-facing changes:

```bash
npm run test:oauth:http:ci
npm run test:network-admin:http:ci
npm run test:slice0:rest-auth:ci
npm run test:slice0:discovery-publication:ci
npm run test:slice0:atomic:matrix
npm run test:slice0:cimd-outbound-safety:ci
```

These environments are disposable proofs. Do not copy prototype code from `tests/Prototype/` into production.

## Verify the distributable

Build the ZIP twice, compare exact bytes, inspect it, exercise install, upgrade, deactivation, uninstall, and run Plugin Check against the artifact:

```bash
npm run artifact:reproducible
npm run artifact:test
npm run secret:check
```

Do not add production Composer dependencies without revisiting the no-`vendor/` distribution contract. Deactivation must retain Charter data. `uninstall.php` and permanent Multisite site deletion must remove only the exact Charter-owned data documented in [Privacy and data retention](docs/privacy.md).
