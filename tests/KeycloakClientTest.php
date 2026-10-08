<?php

declare(strict_types=1);

namespace Bannerstop\Keycloak\Tests;

use Bannerstop\Keycloak\Admin\UserDirectory;
use Bannerstop\Keycloak\Exception\HttpException;
use Bannerstop\Keycloak\KeycloakClient;
use Bannerstop\Keycloak\Login\NativeSessionStateStore;
use Bannerstop\Keycloak\Login\PendingLogin;
use Bannerstop\Keycloak\Tests\Fixtures\FakeHttpClient;
use Bannerstop\Keycloak\Tests\Fixtures\FakeKeycloak;
use Nyholm\Psr7\Factory\Psr17Factory;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\RequestInterface;

final class KeycloakClientTest extends TestCase
{
    public function testLogoutUrl(): void
    {
        $realm = new FakeKeycloak();

        $url = (string) $realm->client()->getLogoutUrl('https://app.example.com/', 'the-id-token');

        self::assertStringStartsWith(FakeKeycloak::ISSUER . '/protocol/openid-connect/logout?', $url);
        parse_str((string) parse_url($url, PHP_URL_QUERY), $query);
        self::assertSame(['client_id' => 'app', 'id_token_hint' => 'the-id-token', 'post_logout_redirect_uri' => 'https://app.example.com/'], $query);
    }

    public function testRefresh(): void
    {
        $realm = new FakeKeycloak();
        $realm->http->on('POST', FakeKeycloak::TOKEN_ENDPOINT, static function (RequestInterface $request): array {
            parse_str((string) $request->getBody(), $body);
            self::assertSame(['grant_type' => 'refresh_token', 'refresh_token' => 'old'], $body);

            return [200, ['access_token' => 'new', 'expires_in' => 300]];
        });

        self::assertSame('new', $realm->client()->refresh('old')->getAccessToken());
    }

    public function testRevokeUsesTheDiscoveredEndpoint(): void
    {
        $realm = new FakeKeycloak();
        $realm->http->on('POST', FakeKeycloak::ISSUER . '/protocol/openid-connect/revoke', [200, []]);

        $realm->client()->revokeRefreshToken('refresh');

        self::assertCount(1, $realm->http->requestsTo('POST', FakeKeycloak::ISSUER . '/protocol/openid-connect/revoke'));
    }

    public function testDiscoveryIsCachedPerClient(): void
    {
        $realm = new FakeKeycloak();
        $client = $realm->client();
        $client->getMetadata();
        $client->getMetadata();

        self::assertCount(1, $realm->http->requestsTo('GET', FakeKeycloak::ISSUER . '/.well-known/openid-configuration'));
    }

    public function testRejectsADiscoveryDocumentOfAnotherIssuer(): void
    {
        $this->expectException(HttpException::class);
        $this->expectExceptionMessage('belongs to the issuer');

        $this->clientWithDiscovery([
            'issuer' => 'https://evil.example/realms/example',
            'authorization_endpoint' => 'https://evil.example/auth',
            'token_endpoint' => 'https://evil.example/token',
            'jwks_uri' => 'https://evil.example/certs',
        ])->getMetadata();
    }

    public function testHttpErrorsCarryTheStatusButNoBody(): void
    {
        $realm = new FakeKeycloak();
        $realm->http->on('POST', FakeKeycloak::TOKEN_ENDPOINT, [401, ['error' => 'invalid_client', 'error_description' => 'details']]);

        try {
            $realm->client()->refresh('old');
            self::fail('No exception.');
        } catch (HttpException $exception) {
            self::assertSame(401, $exception->getStatusCode());
            self::assertStringContainsString('invalid_client', $exception->getMessage());
            self::assertStringNotContainsString('old', $exception->getMessage());
        }
    }

    public function testDirectoryPagesThroughAllUsers(): void
    {
        $realm = new FakeKeycloak();
        $realm->http->on('POST', FakeKeycloak::TOKEN_ENDPOINT, static function (RequestInterface $request): array {
            parse_str((string) $request->getBody(), $body);
            self::assertSame(['grant_type' => 'client_credentials'], $body);

            return [200, ['access_token' => 'service-token', 'expires_in' => 300]];
        });
        $realm->http->on('GET', FakeKeycloak::SERVER . '/admin/realms/example/users', static function (RequestInterface $request): array {
            self::assertSame('Bearer service-token', $request->getHeaderLine('Authorization'));
            parse_str($request->getUri()->getQuery(), $query);
            $users = [];
            for ($i = (int) $query['first']; $i < min(150, (int) $query['first'] + (int) $query['max']); ++$i) {
                $users[] = 50 === $i ? ['username' => 'rows without id are skipped'] : ['id' => 'id-' . $i, 'username' => 'user' . $i, 'email' => 'User' . $i . '@Example.com', 'firstName' => 'User', 'lastName' => (string) $i, 'enabled' => 0 !== $i % 2];
            }

            return [200, $users];
        });

        $users = iterator_to_array((new UserDirectory($realm->client()))->users(), false);

        self::assertCount(149, $users);
        self::assertSame('user0@example.com', $users[0]->getEmail());
        self::assertSame('User 0', $users[0]->getDisplayName());
        self::assertFalse($users[0]->isEnabled());
        self::assertTrue($users[1]->isEnabled());
        self::assertCount(1, $realm->http->requestsTo('POST', FakeKeycloak::TOKEN_ENDPOINT), 'The service token is reused.');
    }

    public function testDirectoryFindReturnsNullForUnknownUsers(): void
    {
        $realm = new FakeKeycloak();
        $realm->http->on('POST', FakeKeycloak::TOKEN_ENDPOINT, [200, ['access_token' => 'service-token', 'expires_in' => 300]]);

        self::assertNull((new UserDirectory($realm->client()))->find('missing'));
    }

    public function testNativeSessionStateStore(): void
    {
        session_id('test' . bin2hex(random_bytes(8)));
        session_start();
        try {
            $store = new NativeSessionStateStore();
            $logins = [];
            for ($i = 0; $i < 7; ++$i) {
                $store->save($logins[] = PendingLogin::start('https://app.example.com/cb', null, 1000));
            }

            self::assertNull($store->take($logins[0]->getState()), 'Only the five newest logins are kept.');
            self::assertEquals($logins[6], $store->take($logins[6]->getState()));
            self::assertNull($store->take($logins[6]->getState()), 'Taken logins are gone.');
            self::assertEquals($logins[5], $store->take($logins[5]->getState()));
        } finally {
            session_destroy();
        }
    }

    /**
     * @param array<string, string> $document
     */
    private function clientWithDiscovery(array $document): KeycloakClient
    {
        $http = new FakeHttpClient();
        $http->on('GET', FakeKeycloak::ISSUER . '/.well-known/openid-configuration', [200, $document]);
        $factory = new Psr17Factory();

        return new KeycloakClient((new FakeKeycloak())->config, $http, $factory, $factory);
    }
}
