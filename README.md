# bannerstop/keycloak

A small, framework-agnostic [Keycloak](https://www.keycloak.org/) / OpenID Connect
client for PHP. It does the security-critical parts once and in one place:

- **Browser login**: authorization code flow with PKCE, state and nonce
- **Token verification** against the realm's JWKS: signature, issuer, audience, expiry
- **Bearer tokens** for APIs
- **Logout** (RP-initiated), refresh and revocation
- **Role mapping** from realm roles, client roles and groups to your application's roles
- **User directory** through the admin REST API and a service account

It only depends on PSR interfaces, so it runs with any HTTP client and inside
any framework. Ready-made integrations:

- Symfony: [bannerstop/keycloak-bundle](https://github.com/bannerstop/keycloak-bundle)
- Laravel: [bannerstop/keycloak-laravel](https://github.com/bannerstop/keycloak-laravel)

## Versions

Each major version targets one minimum PHP version and uses the language
features that come with it. Pick the highest major your PHP version allows;
Composer does this for you with a `*` or a wide constraint.

| Version | PHP     |
|---------|---------|
| 1.x     | ≥ 7.1.3 |

## Installation

```bash
composer require bannerstop/keycloak
```

You also need a [PSR-18](https://www.php-fig.org/psr/psr-18/) HTTP client and
[PSR-17](https://www.php-fig.org/psr/psr-17/) factories, for example:

```bash
composer require guzzlehttp/guzzle               # Guzzle 7, ships both
composer require symfony/http-client nyholm/psr7 # Symfony HttpClient
composer require php-http/guzzle6-adapter         # projects stuck on Guzzle 6
```

## Keycloak setup

1. Create an OpenID Connect client with *Client authentication* on
   (confidential) and the *Standard flow* enabled.
2. Add your callback URL to *Valid redirect URIs* and your logout target to
   *Valid post logout redirect URIs*.
3. Under *Advanced*, set *Proof Key for Code Exchange Code Challenge Method* to `S256`.
4. Optional:
   - **Groups**: add a *Group Membership* mapper (claim `groups`) to the client's
     dedicated scope.
   - **APIs**: add an *Audience* mapper so that access tokens carry the API's
     audience.
   - **Directory**: enable *Service accounts roles* and assign the client role
     `realm-management` → `view-users` to the service account.

## Usage

### Create the client

```php
use Bannerstop\Keycloak\KeycloakClient;
use Bannerstop\Keycloak\KeycloakConfig;
use GuzzleHttp\Client;
use GuzzleHttp\Psr7\HttpFactory;

$config = new KeycloakConfig(
    'https://sso.example.com', // server URL
    'example',                 // realm
    'my-app',                  // client id
    getenv('KEYCLOAK_CLIENT_SECRET') // null for public clients
);
$factory = new HttpFactory();
$keycloak = new KeycloakClient($config, new Client(['timeout' => 10]), $factory, $factory, $psr16Cache);
```

Pass a PSR-16 cache (the 5th argument) in production: the discovery document
and the signing keys are then fetched once per hour instead of once per
request. After a key rotation, the new key is picked up automatically.

### Browser login

```php
use Bannerstop\Keycloak\Exception\LoginException;
use Bannerstop\Keycloak\Login\LoginFlow;
use Bannerstop\Keycloak\Login\NativeSessionStateStore;
use Bannerstop\Keycloak\Login\RedirectTarget;
use Bannerstop\Keycloak\Policy\EmailDomainPolicy;

session_start();
$flow = new LoginFlow($keycloak, new NativeSessionStateStore(), [new EmailDomainPolicy(['example.com'])]);

// login.php
header('Location: ' . $flow->start('https://app.example.com/callback.php', $_GET['return_to'] ?? null));

// callback.php
try {
    $result = $flow->finish($_GET);
} catch (LoginException $exception) {
    // $exception->getReason(): state_mismatch, cancelled, provider_error, invalid_token, not_allowed
}
session_regenerate_id(true);
$identity = $result->getIdentity();
$_SESSION['user'] = $identity->getSubject(); // stable id, use it to link accounts
$_SESSION['tokens'] = $result->getTokens()->toArray();
$target = RedirectTarget::isLocal($result->getReturnTo()) ? $result->getReturnTo() : '/';
header('Location: ' . $target);
```

`Identity` offers `getSubject()`, `getEmail()`, `isEmailVerified()`,
`getDisplayName()`, `getUsername()`, `getRealmRoles()`, `getClientRoles($clientId)`,
`getGroups()` and `getClaims()` for everything else.

### Logout

```php
use Bannerstop\Keycloak\Token\TokenSet;

$tokens = TokenSet::fromArray($_SESSION['tokens']);
session_destroy();
header('Location: ' . $keycloak->getLogoutUrl('https://app.example.com/', $tokens->getIdToken()));
```

### Roles

Only roles and groups you map explicitly are granted:

```php
use Bannerstop\Keycloak\Role\RoleMapper;

$roles = RoleMapper::fromArray([
    'default_roles' => ['ROLE_USER'],
    'realm_roles' => ['admin' => ['ROLE_ADMIN']],
    'client_roles' => ['my-app' => ['editor' => ['ROLE_EDITOR']]],
    'groups' => ['/staff/it' => ['ROLE_IT']],
])->map($identity);
```

### Bearer tokens for APIs

```php
use Bannerstop\Keycloak\Bearer\BearerToken;
use Bannerstop\Keycloak\Exception\InvalidTokenException;

$token = BearerToken::fromAuthorizationHeader($_SERVER['HTTP_AUTHORIZATION'] ?? null);
try {
    $identity = $keycloak->verifyAccessToken((string) $token, 'my-api'); // audience
} catch (InvalidTokenException $exception) {
    http_response_code(401);
    exit;
}
```

### Ending sessions with Keycloak

Logging out of Keycloak, or of another application, does not end the session
of your application by itself. Two mechanisms close that gap; use both.

**Back-channel logout** (OpenID Connect Back-Channel Logout 1.0): Keycloak
posts a signed logout token to your application when a session ends. Set the
client's *Backchannel logout URL* and turn on *Backchannel logout session
required*, then record the token:

```php
use Bannerstop\Keycloak\Exception\KeycloakException;
use Bannerstop\Keycloak\Session\SessionRevocations;

// POST /keycloak/backchannel-logout - no session, no CSRF token
$revocations = new SessionRevocations($psr16Cache, 8 * 3600); // shared by all web servers
try {
    $accepted = $revocations->revoke($keycloak->verifyLogoutToken((string) ($_POST['logout_token'] ?? '')));
} catch (KeycloakException $exception) {
    $accepted = false;
}
http_response_code($accepted ? 200 : 400); // false also means: replayed token
```

**Session check**: keep a `KeycloakSession` next to your login and check it on
every request. It ends sessions that Keycloak revoked through the back channel,
and every `$interval` seconds it redeems the refresh token, which fails once the
Keycloak session is gone (logout elsewhere, user disabled, SSO session
expired). If Keycloak is unreachable, the session is kept.

```php
use Bannerstop\Keycloak\Session\KeycloakSession;
use Bannerstop\Keycloak\Session\SessionCheck;

// after the login
$_SESSION['keycloak'] = KeycloakSession::fromLogin($result, $keycloak->now())->toArray();

// on every request
$session = KeycloakSession::fromArray($_SESSION['keycloak'] ?? []);
$checked = null === $session ? null : (new SessionCheck($keycloak, $revocations, 300))->check($session);
if (null === $checked) {
    // log the user out
} else {
    $_SESSION['keycloak'] = $checked->toArray();
}
```

Keycloak does not always send a back-channel call for every session (e.g. when
an administrator signs a user out of all sessions), so keep the interval check
switched on as a safety net.

### User directory

```php
use Bannerstop\Keycloak\Admin\UserDirectory;

foreach ((new UserDirectory($keycloak))->users() as $user) {
    // $user->getId() equals the "sub" of the user's tokens
}
```

## Security

See [SECURITY.md](SECURITY.md) for what the library checks, what is left to
you, and how to report a vulnerability.

## Development

```bash
composer install
vendor/bin/phpunit
```

`tests-e2e/` runs the library against a real Keycloak in Docker, see its README.

## License

MIT, see [LICENSE](LICENSE).
