# Security policy

## Supported versions

Security fixes are provided for the latest `0.1.x` development release.

Read the [runtime security model](docs/security-model.md) for credential, client, Multisite, outbound-request, signing-key, containment, and deletion boundaries. Read [Privacy and data retention](docs/privacy.md) for stored data, outbound Client ID Metadata Document requests, retention periods, and removal behavior.

## Report a vulnerability

Do not disclose a suspected vulnerability in a public issue or discussion.

Contact Ovidiu Galatan through a private contact method listed on the [maintainer's GitHub profile](https://github.com/galatanovidiu). Include the affected version, reproduction steps, impact, and any suggested mitigation.

You should receive an acknowledgement within seven days. Coordinated disclosure timing depends on the severity and the availability of a verified fix.

Do not include access tokens, refresh tokens, authorization codes, client secrets, WordPress salts, `CHARTER_SECRET_KEY`, raw database exports, or production user data in a report. Use synthetic values and the smallest reproducible environment.
