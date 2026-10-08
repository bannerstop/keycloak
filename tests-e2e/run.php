<?php

declare(strict_types=1);

/*
 * End-to-end check against a real Keycloak (see README.md in this directory).
 * Drives the browser login with plain curl, everything else goes through the library.
 */

use Bannerstop\Keycloak\Admin\UserDirectory;
use Bannerstop\Keycloak\Exception\InvalidTokenException;
use Bannerstop\Keycloak\Exception\LoginException;
use Bannerstop\Keycloak\KeycloakClient;
use Bannerstop\Keycloak\KeycloakConfig;
use Bannerstop\Keycloak\Login\LoginFlow;
use Bannerstop\Keycloak\Login\NativeSessionStateStore;
use Bannerstop\Keycloak\Policy\EmailDomainPolicy;
use Bannerstop\Keycloak\Role\RoleMapper;
use Nyholm\Psr7\Factory\Psr17Factory;

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

function httpClient(): Psr\Http\Client\ClientInterface
{
    if (class_exists(Http\Adapter\Guzzle6\Client::class)) {
        return Http\Adapter\Guzzle6\Client::createWithConfig(['timeout' => 10]);
    }

    return new Symfony\Component\HttpClient\Psr18Client();
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
    $html = (string) curl_exec($curl);
    if (1 !== preg_match('/<form[^>]+id="kc-form-login"[^>]+action="([^"]+)"/', $html, $match)) {
        throw new RuntimeException('No login form: ' . substr($html, 0, 300));
    }
    curl_setopt_array($curl, [
        CURLOPT_URL => html_entity_decode($match[1]),
        CURLOPT_POST => true,
        CURLOPT_POSTFIELDS => http_build_query(['username' => $username, 'password' => $password, 'credentialId' => '']),
        CURLOPT_HEADER => true,
    ]);
    $response = (string) curl_exec($curl);
    if (1 !== preg_match('/^Location: (\S+)/mi', $response, $location)) {
        throw new RuntimeException('Login did not redirect: ' . substr($response, 0, 300));
    }
    parse_str((string) parse_url($location[1], PHP_URL_QUERY), $query);
    curl_close($curl);

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
echo 'PHP ' . PHP_VERSION . ' with ' . get_class(httpClient()) . "\n";

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
    check(LoginException::STATE_MISMATCH === $exception->getReason(), 'replayed callback is rejected');
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
    check(false !== strpos($exception->getMessage(), 'type'), 'ID token rejected as bearer token');
}

// Refresh and userinfo
$refreshed = $client->refresh((string) $result->getTokens()->getRefreshToken());
check($client->getIdentity($refreshed, null)->getSubject() === $identity->getSubject(), 'refreshed tokens verify');
check('jane.doe@example.com' === $client->getUserInfo($refreshed->getAccessToken())->getString('email'), 'userinfo endpoint');

// Directory through the service account
$users = [];
foreach ((new UserDirectory($client))->users() as $user) {
    $users[$user->getUsername()] = $user;
}
check(isset($users['jdoe']) && $users['jdoe']->getId() === $identity->getSubject(), 'directory lists jdoe with the token subject as id');
check(['/staff/it'] === (new UserDirectory($client))->groupsOf($identity->getSubject()), 'directory reads group paths');
check(null === (new UserDirectory($client))->find('00000000-0000-0000-0000-000000000000'), 'directory returns null for unknown ids');

// RP-initiated logout ends the Keycloak session
$logoutUrl = (string) $client->getLogoutUrl('http://app.test/', $refreshed->getIdToken());
$curl = curl_init($logoutUrl);
curl_setopt_array($curl, [CURLOPT_RETURNTRANSFER => true, CURLOPT_HEADER => true]);
$response = (string) curl_exec($curl);
check(1 === preg_match('~^Location: http://app\.test/~mi', $response), 'logout redirects back to the application');
try {
    $client->refresh((string) $refreshed->getRefreshToken());
    check(false, 'refresh token is dead after logout');
} catch (Bannerstop\Keycloak\Exception\HttpException $exception) {
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
    check(LoginException::NOT_ALLOWED === $exception->getReason(), 'policy rejects other e-mail domains');
}

echo "all checks passed\n";
