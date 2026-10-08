# Security policy

## Reporting a vulnerability

Please do not open a public issue for security problems. Report them privately,
either by e-mail to [dev@bannerstop.com](mailto:dev@bannerstop.com) or through
GitHub: open the **Security** tab of this repository and choose **Report a
vulnerability**. We will get back to you and keep you posted until a fix is
released.

## Supported versions

Every major version targets one minimum PHP version (see the README). Security
fixes go into the latest major first. Because the older majors exist for legacy
applications, we try to backport fixes to them as well, as long as the fix
does not need a newer PHP version.

## What the library guarantees

- Tokens are only accepted with a valid signature of a key from the realm's
  JWKS. `none` and symmetric algorithms (`HS*`) are never accepted, and only the
  algorithms you configure (default: `RS256`) are tried.
- ID tokens are checked for issuer, audience, authorized party, expiry, issue
  time and nonce (OpenID Connect Core 3.1.3.7). Access tokens are checked for
  issuer, expiry, type and audience.
- Every login uses PKCE (S256), a fresh state and a fresh nonce, and the
  callback's issuer is checked (RFC 9207). A pending login can be completed
  once and expires after ten minutes.
- The "return to" URL of a login is stored as given; `RedirectTarget::isLocal()`
  and the framework integrations only redirect to local paths.
- Secrets and tokens are hidden from `var_dump()` and never written to
  exception messages.

## What you have to do

- Talk to Keycloak over HTTPS only.
- Keep the client secret out of version control.
- Store `TokenSet::toArray()` only server-side (session), never in cookies or
  local storage.
- For APIs, add an audience mapper in Keycloak and verify the audience.
