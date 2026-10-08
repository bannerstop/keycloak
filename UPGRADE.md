# Upgrade guide

Each major version raises the minimum PHP version. Only the steps that need
changes in your code are listed.

## 9.x → 10.x

- PHP 8.5 or later is required.
- PHP now warns when the result of `RoleMapper::with*()`, `LoginFlow::start()`,
  `KeycloakClient::getAuthorizationUrl()`, `KeycloakClient::getLogoutUrl()` or
  `RedirectTarget::isLocal()` is ignored. Ignoring it was a bug before, too;
  use the result, or cast the call to `(void)` where ignoring it is intended.
- `RoleMapper::__construct()` takes the realm role, client role and group
  mappings as further optional arguments.

## 8.x → 9.x

- PHP 8.4 or later is required.
- `psr/http-message` 2, `psr/http-factory` 1.1 and `psr/simple-cache` 2 or 3
  are required. Update your HTTP client and cache packages if Composer reports
  a conflict.

## 7.x → 8.x

- PHP 8.3 or later is required. No code changes needed.

## 6.x → 7.x

- PHP 8.2 or later is required. No code changes needed.

## 5.x → 6.x

- PHP 8.1 or later is required.
- Replace `LoginException::STATE_MISMATCH` and the other reason constants with
  `LoginFailure::StateMismatch`, `Cancelled`, `ProviderError`, `InvalidToken`
  and `NotAllowed`. `getReason()` returns the enum; use `->value` where you
  need the old string, e.g. for translation keys.
- Pass `Algorithm::RS256` instead of `'RS256'` to the `KeycloakConfig`
  constructor. `KeycloakConfig::fromArray()` keeps accepting strings.
  `Algorithm::all()` is now `Algorithm::names()`.
- Do not pass `null` as clock to `KeycloakClient`; leave the argument out.

## 4.x → 5.x

- PHP 8.0 or later is required.
- `Claims::get()`, `Claims::getPath()` declare `mixed` as return type. Code
  that extends these classes is not affected, because they are final.

## 3.x → 4.x

- PHP 7.4 or later is required. No code changes needed.

## 2.x → 3.x

- PHP 7.3 or later is required. No code changes needed.

## 1.x → 2.x

- PHP 7.2 or later is required. No code changes needed.
