# Changelog

All notable changes to this project are documented here. The project follows
[Semantic Versioning](https://semver.org/). Each major version raises the
minimum PHP version and uses the language features that come with it.

## 3.0.1

- Security: the login callback is checked against mix-up attacks (RFC 9207).
  A callback whose `iss` parameter names another issuer is rejected, and so is
  a callback without `iss` if the provider announces that it always sends one
  (`authorization_response_iss_parameter_supported`, which Keycloak does).
  Both fail with the reason `LoginException::PROVIDER_ERROR` before the code is redeemed.

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
