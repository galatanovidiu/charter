# Integrate with Charter OAuth

Charter implements an OAuth 2.1 authorization server profile for WordPress. Discover capabilities from metadata instead of hard-coding endpoint paths.

## Discover an issuer

The WordPress bare origin is both the issuer and the default protected-resource identifier.

- RFC 8414 authorization-server metadata: `https://example.com/.well-known/oauth-authorization-server`
- RFC 9728 default protected-resource metadata: `https://example.com/.well-known/oauth-protected-resource`

Path resources use the RFC 9728 well-known suffix followed by the resource path. Prepared metadata identifies the issuer and resource but does not advertise disabled operational capabilities.

## Use the supported client profile

Charter supports Authorization Code with mandatory PKCE S256.

- Public clients use `token_endpoint_auth_method=none`.
- Confidential clients use `client_secret_post` and receive a secret once.
- HTTP Basic client authentication is not supported.
- Exact redirect matching is required. HTTP local callbacks may use exact `localhost`, `127.0.0.1`, or `[::1]` hosts, and may vary only the runtime port.
- Access tokens are opaque and valid for one hour.
- Authorization codes are single-use and valid for five minutes.
- Continuing access uses rotating refresh tokens with replay-family containment, a 90-day inactivity limit, and a one-year absolute grant limit.
- RFC 7009 revocation accepts access and refresh tokens and closes the complete grant.

Use the exact endpoints advertised in RFC 8414 metadata. Token, registration, and revocation requests are form or JSON requests as defined by their advertised protocol endpoints; Charter does not enable browser CORS for credential endpoints.

## Register a client

Choose one registration model:

- Ask an administrator to pre-register a public or confidential client.
- Use the advertised RFC 7591 registration endpoint while Dynamic Client Registration is enabled.
- Use an exact HTTPS Client ID Metadata Document URL as `client_id`.

Dynamic registration accepts explicit public `none` and confidential `client_secret_post` clients. It does not issue registration management credentials. Anonymous registration is rate-limited by source, issuer, and unused-client inventory.

A Client ID Metadata Document client must be public. The HTTPS document must identify itself with the exact URL, publish accepted redirects, and satisfy Charter's bounded media, size, caching, DNS, address, TLS, and no-redirect policy. Failed or stale metadata never becomes authorization authority.

## Request authorization

Send the parameters required by the advertised authorization endpoint, including:

- `response_type=code`
- The exact `client_id`
- An exact registered `redirect_uri`
- A PKCE `code_challenge` with `code_challenge_method=S256`
- The exact `resource`
- A registered scope set
- `state` for client request correlation

The default resource supports `wordpress:access`. Request `offline_access` only when the client registration permits refresh tokens and the user intends continuing access.

## Protect a WordPress REST handler

Wrap the exact handler array passed to `register_rest_route()`:

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

The default assignment requires `wordpress:access` for the site's canonical resource. Charter authenticates the represented WordPress user before the existing `permission_callback` runs and restores the prior request identity afterward.

Public handlers, cookie and nonce authentication, and Application Passwords remain WordPress-owned. A request that combines an existing WordPress identity with a Charter Bearer credential is rejected.

## Register narrower resources and scopes

Use the `charter_oauth_register_access` action. It receives the request-local `AccessPolicy` and exact issuer:

```php
use GalatanOvidiu\Charter\OAuth\AccessPolicy;

add_action(
	'charter_oauth_register_access',
	static function ( AccessPolicy $policy, string $issuer ): void {
		$resource = $issuer . '/wp-json/example/v1';

		if ( ! $policy->registerResource( 'example-plugin', $resource ) ) {
			return;
		}

		$policy->registerScope(
			'example-plugin',
			'example-plugin:records.read',
			'Read example records',
			'Read records provided by Example Plugin.',
			array( $resource )
		);
	},
	10,
	2
);
```

Owner names must be lowercase namespaces. Specialized scopes must begin with the same owner and a colon. Register the resource before its scopes. Registrations are rebuilt for every security decision; a resource or scope that is no longer registered fails closed for new authorization, exchange, refresh, and access-token use.

Pass the required scope list as the second argument and the same exact resource as the third argument to `ProtectedRoute::assign()` for specialized handlers.

## Handle errors and challenges

Treat OAuth error identifiers as protocol outcomes, not as user-facing diagnostics. A protected route returns an RFC 6750 Bearer challenge that references the exact RFC 9728 metadata URL. Do not infer whether an unknown token, client secret, or revoked credential ever existed.

Retry `temporarily_unavailable` only with bounded backoff. It can indicate an administrator issuance pause. An `invalid_token` response can indicate an invalid credential or issuer lockdown; Charter deliberately keeps that boundary non-revealing.
