<?php

declare(strict_types=1);

/*
 * End-to-end check against a real Keycloak (see README.md in this directory).
 * Drives the browser login with plain curl, everything else goes through the library.
 */
use Psr\Http\Client\ClientInterface;
use GuzzleHttp\Client;
use Symfony\Component\HttpClient\Psr18Client;
use Bannerstop\Keycloak\Exception\HttpException;
use Bannerstop\Keycloak\Admin\UserDirectory;
use Bannerstop\Keycloak\Exception\InvalidTokenException;
use Bannerstop\Keycloak\Exception\LoginException;
use Bannerstop\Keycloak\Exception\LoginFailure;
use Bannerstop\Keycloak\KeycloakClient;
use Bannerstop\Keycloak\KeycloakConfig;
use Bannerstop\Keycloak\Login\LoginFlow;
use Bannerstop\Keycloak\Login\NativeSessionStateStore;
use Bannerstop\Keycloak\Policy\EmailDomainPolicy;
use Bannerstop\Keycloak\Role\RoleMapper;
use Bannerstop\Keycloak\Session\KeycloakSession;
use Bannerstop\Keycloak\Session\SessionCheck;
use Bannerstop\Keycloak\Session\SessionRevocations;
use Nyholm\Psr7\Factory\Psr17Factory;
use Symfony\Component\Cache\Adapter\FilesystemAdapter;
use Symfony\Component\Cache\Psr16Cache;

require __DIR__ . '/vendor/autoload.php';

$server = getenv('KEYCLOAK_URL') ?: 'http://keycloak:8080';
$callback = 'http://app.test/callback';

function check(bool $condition, string $what): void
{
    echo ($condition ? 'ok   ' : 'FAIL ') . $what . "\n";
    if (!$condition) {
        exit(1);
    }
}

function httpClient(): ClientInterface
{
    if (class_exists(Client::class) && is_subclass_of(Client::class, ClientInterface::class)) {
        return new Client(['timeout' => 10]);
    }
    if (class_exists(Http\Adapter\Guzzle6\Client::class)) {
        return Http\Adapter\Guzzle6\Client::createWithConfig(['timeout' => 10]);
    }

    return new Psr18Client();
}

/**
 * Logs in at Keycloak like a browser would and returns the callback query.
 *
 * @return array<string, string>
 */
function browserLogin(string $authorizationUrl, string $username, string $password): array
{
    $cookies = tempnam(sys_get_temp_dir(), 'kc');
    $curl = curl_init($authorizationUrl);
    curl_setopt_array($curl, [CURLOPT_RETURNTRANSFER => true, CURLOPT_COOKIEJAR => $cookies, CURLOPT_COOKIEFILE => $cookies]);
    $form = Dom\HTMLDocument::createFromString((string) curl_exec($curl), LIBXML_NOERROR)->getElementById('kc-form-login')
        ?? throw new RuntimeException('Keycloak shows no login form.');
    curl_setopt_array($curl, [
        CURLOPT_URL => $form->getAttribute('action'),
        CURLOPT_POST => true,
        CURLOPT_POSTFIELDS => http_build_query(['username' => $username, 'password' => $password, 'credentialId' => '']),
    ]);
    curl_exec($curl);
    $location = curl_getinfo($curl, CURLINFO_REDIRECT_URL) ?: throw new RuntimeException('The login did not redirect.');
    parse_str((string) parse_url($location, PHP_URL_QUERY), $query);

    return $query;
}

ini_set('session.use_cookies', '0');
ini_set('session.cache_limiter', '');
session_start();

$factory = new Psr17Factory();
$client = new KeycloakClient(
    new KeycloakConfig($server, 'example', 'app', 'app-secret'),
    httpClient(),
    $factory,
    $factory
);
echo 'PHP ' . PHP_VERSION . ' with ' . httpClient()::class . "\n";

$flow = new LoginFlow($client, new NativeSessionStateStore(), [new EmailDomainPolicy(['example.com'])]);

// Browser login, confidential client
$query = browserLogin($flow->start($callback, '/orders'), 'jdoe', 'jane-password');
check(isset($query['code'], $query['state']), 'Keycloak redirects back with code and state');
check(($query['iss'] ?? null) === $client->getConfig()->getIssuer(), 'Keycloak names itself in the callback (RFC 9207)');
$result = $flow->finish($query);
$identity = $result->getIdentity();
check('jane.doe@example.com' === $identity->getEmail() && $identity->isEmailVerified(), 'identity has the verified e-mail');
check('Jane Doe' === $identity->getDisplayName() && 'jdoe' === $identity->getUsername(), 'identity has name and username');
check(in_array('admin', $identity->getRealmRoles(), true), 'realm role from the access token');
check(['editor'] === $identity->getClientRoles('app'), 'client role from the access token');
check(['/staff/it'] === $identity->getGroups(), 'group path from the access token');
check('/orders' === $result->getReturnTo(), 'return path survives the round trip');

$roles = RoleMapper::fromArray([
    'default_roles' => ['ROLE_USER'],
    'realm_roles' => ['admin' => ['ROLE_ADMIN']],
    'client_roles' => ['app' => ['editor' => ['ROLE_EDITOR']]],
    'groups' => ['/staff/it' => ['ROLE_IT']],
])->map($identity);
check(['ROLE_USER', 'ROLE_ADMIN', 'ROLE_EDITOR', 'ROLE_IT'] === $roles, 'role mapping: ' . implode(', ', $roles));

try {
    $flow->finish($query);
    check(false, 'replayed callback is rejected');
} catch (LoginException $exception) {
    check(LoginFailure::StateMismatch === $exception->getReason(), 'replayed callback is rejected');
}

// Bearer tokens
$bearer = $client->verifyAccessToken($result->getTokens()->getAccessToken(), 'api');
check($bearer->getSubject() === $identity->getSubject(), 'access token accepted for audience "api"');
try {
    $client->verifyAccessToken($result->getTokens()->getAccessToken(), 'billing');
    check(false, 'access token rejected for another audience');
} catch (InvalidTokenException $exception) {
    check(true, 'access token rejected for another audience');
}
try {
    $client->verifyAccessToken((string) $result->getTokens()->getIdToken(), 'app');
    check(false, 'ID token rejected as bearer token');
} catch (InvalidTokenException $exception) {
    check(str_contains($exception->getMessage(), 'type'), 'ID token rejected as bearer token');
}

// Refresh and userinfo
$refreshed = $client->refresh((string) $result->getTokens()->getRefreshToken());
check($client->getIdentity($refreshed, null)->getSubject() === $identity->getSubject(), 'refreshed tokens verify');
check('jane.doe@example.com' === $client->getUserInfo($refreshed->getAccessToken())->getString('email'), 'userinfo endpoint');

// Directory through the service account
$users = [];
foreach (new UserDirectory($client)->users() as $user) {
    $users[$user->getUsername()] = $user;
}
check(isset($users['jdoe']) && $users['jdoe']->getId() === $identity->getSubject(), 'directory lists jdoe with the token subject as id');
check(['/staff/it'] === new UserDirectory($client)->groupsOf($identity->getSubject()), 'directory reads group paths');
check(null === new UserDirectory($client)->find('00000000-0000-0000-0000-000000000000'), 'directory returns null for unknown ids');

// RP-initiated logout ends the Keycloak session
$logoutUrl = (string) $client->getLogoutUrl('http://app.test/', $refreshed->getIdToken());
$curl = curl_init($logoutUrl);
curl_setopt($curl, CURLOPT_RETURNTRANSFER, true);
curl_exec($curl);
check(str_starts_with((string) curl_getinfo($curl, CURLINFO_REDIRECT_URL), 'http://app.test/'), 'logout redirects back to the application');
try {
    $client->refresh((string) $refreshed->getRefreshToken());
    check(false, 'refresh token is dead after logout');
} catch (HttpException $exception) {
    check(400 === $exception->getStatusCode(), 'refresh token is dead after logout');
}

// Public client with PKCE only
$publicFlow = new LoginFlow(
    new KeycloakClient(new KeycloakConfig($server, 'example', 'public-app'), httpClient(), $factory, $factory),
    new NativeSessionStateStore()
);
$publicResult = $publicFlow->finish(browserLogin($publicFlow->start($callback), 'jdoe', 'jane-password'));
check($publicResult->getIdentity()->getSubject() === $identity->getSubject(), 'public client login with PKCE');

// The policy rejects other domains
$strictFlow = new LoginFlow($client, new NativeSessionStateStore(), [new EmailDomainPolicy(['example.org'])]);
try {
    $strictFlow->finish(browserLogin($strictFlow->start($callback), 'jdoe', 'jane-password'));
    check(false, 'policy rejects other e-mail domains');
} catch (LoginException $exception) {
    check(LoginFailure::NotAllowed === $exception->getReason(), 'policy rejects other e-mail domains');
}

// Back-channel logout: Keycloak tells the application that a session ended elsewhere
/**
 * @param array<string, mixed>|null $body
 */
function adminApi(string $server, string $method, string $path, ?array $body = null): mixed
{
    static $token;
    if (null === $token) {
        $curl = curl_init($server . '/realms/master/protocol/openid-connect/token');
        curl_setopt_array($curl, [CURLOPT_RETURNTRANSFER => true, CURLOPT_POSTFIELDS => http_build_query(['grant_type' => 'password', 'client_id' => 'admin-cli', 'username' => 'admin', 'password' => 'admin'])]);
        $token = json_decode((string) curl_exec($curl), true)['access_token'];
    }
    $curl = curl_init($server . '/admin/realms/example' . $path);
    curl_setopt_array($curl, [
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_CUSTOMREQUEST => $method,
        CURLOPT_HTTPHEADER => ['Authorization: Bearer ' . $token, 'Content-Type: application/json'],
        CURLOPT_POSTFIELDS => null === $body ? '' : json_encode($body),
    ]);
    $response = (string) curl_exec($curl);
    $status = curl_getinfo($curl, CURLINFO_RESPONSE_CODE);
    if ($status >= 300) {
        throw new RuntimeException(sprintf('%s %s returned HTTP %d.', $method, $path, $status));
    }

    return json_decode($response, true);
}

$backchannelServer = proc_open([PHP_BINARY, '-S', '0.0.0.0:8000', __DIR__ . '/backchannel.php'], [1 => ['file', '/dev/null', 'w'], 2 => ['file', sys_get_temp_dir() . '/backchannel.log', 'w']], $pipes, __DIR__, array_merge(getenv(), ['PHP_CLI_SERVER_WORKERS' => '4']));
register_shutdown_function(static fn () => proc_terminate($backchannelServer));
$appClient = adminApi($server, 'GET', '/clients?clientId=app')[0];
adminApi($server, 'PUT', '/clients/' . $appClient['id'], ['clientId' => 'app', 'attributes' => [
    'backchannel.logout.url' => getenv('BACKCHANNEL_URL') ?: 'http://e2e-app:8000/',
    'backchannel.logout.session.required' => 'true',
]]);

$revocations = new SessionRevocations(new Psr16Cache(new FilesystemAdapter('revocations', 0, sys_get_temp_dir() . '/keycloak-e2e')), 3600);

$backchannelFlow = new LoginFlow($client, new NativeSessionStateStore());
$login = $backchannelFlow->finish(browserLogin($backchannelFlow->start($callback), 'jdoe', 'jane-password'));
$session = KeycloakSession::fromLogin($login, $client->now());
check(null !== $session->getSessionId(), 'the ID token names the Keycloak session (sid)');
check(null !== (new SessionCheck($client, $revocations))->check($session), 'a fresh session passes the check');

adminApi($server, 'DELETE', '/sessions/' . $session->getSessionId());
for ($waited = 0; $waited < 50 && !$revocations->isRevoked($session); ++$waited) {
    usleep(100000);
}
check(null === (new SessionCheck($client, $revocations))->check($session), 'a session ended in Keycloak ends through the back channel');

// Refresh check: without the back channel, the next refresh tells that the Keycloak session is gone
$login = $backchannelFlow->finish(browserLogin($backchannelFlow->start($callback), 'jdoe', 'jane-password'));
$session = KeycloakSession::fromLogin($login, $client->now() - 120);
$refreshCheck = new SessionCheck($client, null, 60);
$session = $refreshCheck->check($session);
check(null !== $session && $session->getCheckedAt() >= $client->now() - 5, 'the refresh check renews a live session');
adminApi($server, 'DELETE', '/sessions/' . $session->getSessionId());
check(null === $refreshCheck->check($session->withCheckedAt($client->now() - 120)), 'the refresh check ends a session Keycloak ended');

echo "all checks passed\n";
