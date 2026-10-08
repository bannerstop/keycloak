# Upgrade guide

Each major version raises the minimum PHP version. Only the steps that need
changes in your code are listed.

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
