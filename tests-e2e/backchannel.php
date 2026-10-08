<?php

declare(strict_types=1);

/*
 * The back-channel logout endpoint of the end-to-end test, served by
 * `php -S` from run.php. Keycloak posts the logout token here.
 */

use Bannerstop\Keycloak\Exception\KeycloakException;
use Bannerstop\Keycloak\KeycloakClient;
use Bannerstop\Keycloak\KeycloakConfig;
use Bannerstop\Keycloak\Session\SessionRevocations;
use Nyholm\Psr7\Factory\Psr17Factory;
use Symfony\Component\Cache\Adapter\FilesystemAdapter;
use Symfony\Component\Cache\Psr16Cache;
use Symfony\Component\HttpClient\Psr18Client;

require __DIR__ . '/vendor/autoload.php';

$factory = new Psr17Factory();
$client = new KeycloakClient(
    new KeycloakConfig(getenv('KEYCLOAK_URL') ?: 'http://keycloak:8080', 'example', 'app', 'app-secret'),
    class_exists(Psr18Client::class) ? new Psr18Client() : new GuzzleHttp\Client(['timeout' => 10]),
    $factory,
    $factory
);
$revocations = new SessionRevocations(new Psr16Cache(new FilesystemAdapter('revocations', 0, sys_get_temp_dir() . '/keycloak-e2e')), 3600);

$logoutToken = $_POST['logout_token'] ?? null;
try {
    $accepted = is_string($logoutToken) && $revocations->revoke($client->verifyLogoutToken($logoutToken));
} catch (KeycloakException $exception) {
    error_log('back-channel logout rejected: ' . $exception->getMessage());
    $accepted = false;
}

http_response_code($accepted ? 200 : 400);
header('Cache-Control: no-store');
