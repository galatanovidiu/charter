# Contributing to Charter

## Prepare your environment

Charter requires PHP 8.4 or later, Composer 2, Node.js 24, npm 11 or later, and Docker.

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
```

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

## Verify the distributable

Build, inspect, install, activate, and run Plugin Check against the same ZIP used by continuous integration:

```bash
npm run build:zip
npm run artifact:verify
npm run artifact:test
```

Do not add production Composer dependencies without revisiting the no-`vendor/` distribution contract. Do not add `uninstall.php` until data-retention behavior is explicitly defined.
