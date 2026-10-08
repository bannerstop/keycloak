# Changelog

All notable changes to this project are documented here. The project follows
[Semantic Versioning](https://semver.org/). Each major version raises the
minimum PHP version and uses the language features that come with it.

## 8.0.0

- Requires PHP 8.3 or later.
- Typed class constants and `#[\Override]` on every implemented interface
  method.

## 7.0.0

- Requires PHP 8.2 or later.
- Value objects are readonly classes.
- Client secret, tokens, authorization codes and the PKCE verifier are marked
  `#[\SensitiveParameter]`, so they no longer show up in stack traces.

## 6.0.0

- Requires PHP 8.1 or later.
- `Algorithm` is a backed enum. `KeycloakConfig` takes and returns `Algorithm`
  cases; `KeycloakConfig::fromArray()` still accepts names like `"RS256"`.
- `LoginException::getReason()` returns the new `LoginFailure` enum instead of
  a string. The enum values are the former strings.
- `KeycloakClient` defaults its clock to `SystemClock` instead of `null`.
- Readonly properties throughout.

## 5.0.0

- Requires PHP 8.0 or later.
- Constructor property promotion, `mixed`, `match`, `throw` expressions and
  `str_contains()` throughout.
- Multi-line parameter lists end with a trailing comma.

## 4.0.0

- Requires PHP 7.4 or later.
- Typed properties and arrow functions throughout.

## 3.0.0

- Requires PHP 7.3 or later.
- JSON from tokens and from Keycloak is decoded with `JSON_THROW_ON_ERROR`;
  malformed documents are reported as before (`InvalidTokenException`,
  `HttpException`).

## 2.0.0

- Requires PHP 7.2 or later. The API is unchanged; the major version marks the
  new PHP range (see UPGRADE.md).

## 1.0.0

First release, PHP 7.1.3 and later.

- Browser login (authorization code flow with PKCE, state and nonce)
- Token verification against the realm's JWKS (RS256/384/512, ES256/384/512, EdDSA)
- Bearer token verification for APIs, with audience check
- RP-initiated logout, refresh, revocation, userinfo
- Role mapping from realm roles, client roles and groups
- E-mail domain policy for logins
- Admin API user directory through a service account
