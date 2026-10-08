# Changelog

All notable changes to this project are documented here. The project follows
[Semantic Versioning](https://semver.org/). Each major version raises the
minimum PHP version and uses the language features that come with it.

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
