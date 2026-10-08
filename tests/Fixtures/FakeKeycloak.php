<?php

declare(strict_types=1);

namespace Bannerstop\Keycloak\Tests\Fixtures;

use Bannerstop\Keycloak\Jwt\Algorithm;
use Bannerstop\Keycloak\KeycloakClient;
use Bannerstop\Keycloak\KeycloakConfig;
use Nyholm\Psr7\Factory\Psr17Factory;

/**
 * A realm "example" on https://sso.example.com, served by FakeHttpClient.
 */
final class FakeKeycloak
{
    public const SERVER = 'https://sso.example.com';
    public const ISSUER = 'https://sso.example.com/realms/example';
    public const TOKEN_ENDPOINT = self::ISSUER . '/protocol/openid-connect/token';
    public const JWKS_URI = self::ISSUER . '/protocol/openid-connect/certs';
    public const NOW = 1750000000;

    public FakeHttpClient $http;
    public FrozenClock $clock;
    public TestKey $key;
    public KeycloakConfig $config;

    /** @var array<int, array<string, string>> */
    private array $publishedKeys;

    /**
     * @param string[] $allowedAlgorithms
     */
    /** Whether the discovery document announces RFC 9207 "iss" in callbacks. */
    public bool $sendsIssuerParameter = false;

    public function __construct(
        ?TestKey $key = null,
        array $allowedAlgorithms = ['RS256'],
        ?string $clientSecret = 'secret',
    ) {
        $this->http = new FakeHttpClient();
        $this->clock = new FrozenClock(self::NOW);
        $this->key = $key ?? self::sharedRsaKey();
        $this->publishedKeys = [$this->key->jwk()];
        $this->config = new KeycloakConfig(self::SERVER, 'example', 'app', $clientSecret, ['openid', 'email', 'profile'], array_map(Algorithm::from(...), $allowedAlgorithms));

        $this->http->on('GET', self::ISSUER . '/.well-known/openid-configuration', fn (): array => [200, [
            'issuer' => self::ISSUER,
            'authorization_response_iss_parameter_supported' => $this->sendsIssuerParameter,
            'authorization_endpoint' => self::ISSUER . '/protocol/openid-connect/auth',
            'token_endpoint' => self::TOKEN_ENDPOINT,
            'userinfo_endpoint' => self::ISSUER . '/protocol/openid-connect/userinfo',
            'end_session_endpoint' => self::ISSUER . '/protocol/openid-connect/logout',
            'revocation_endpoint' => self::ISSUER . '/protocol/openid-connect/revoke',
            'jwks_uri' => self::JWKS_URI,
        ]]);
        $this->http->on('GET', self::JWKS_URI, fn (): array => [200, ['keys' => $this->publishedKeys]]);
    }

    public static function sharedRsaKey(): TestKey
    {
        static $key;

        return $key ?? $key = TestKey::rsa();
    }

    /**
     * @param array<string, string>[] $jwks
     */
    public function publishKeys(array $jwks): void
    {
        $this->publishedKeys = $jwks;
    }

    public function client(): KeycloakClient
    {
        $factory = new Psr17Factory();

        return new KeycloakClient($this->config, $this->http, $factory, $factory, null, $this->clock);
    }

    /**
     * @param array<string, mixed> $overrides null values remove a claim
     *
     * @return array<string, mixed>
     */
    public static function idClaims(array $overrides = []): array
    {
        return self::claims(array_merge([
            'typ' => 'ID',
            'aud' => 'app',
            'azp' => 'app',
            'nonce' => 'the-nonce',
            'email' => 'Jane.Doe@Example.com',
            'email_verified' => true,
            'name' => 'Jane Doe',
            'preferred_username' => 'jdoe',
        ], $overrides));
    }

    /**
     * @param array<string, mixed> $overrides
     *
     * @return array<string, mixed>
     */
    public static function accessClaims(array $overrides = []): array
    {
        return self::claims(array_merge([
            'typ' => 'Bearer',
            'aud' => ['api', 'account'],
            'azp' => 'app',
            'realm_access' => ['roles' => ['admin', 'offline_access']],
            'resource_access' => ['app' => ['roles' => ['editor']]],
            'groups' => ['/staff/it'],
        ], $overrides));
    }

    /**
     * @param array<string, mixed> $overrides
     *
     * @return array<string, mixed>
     */
    private static function claims(array $overrides): array
    {
        $claims = array_merge([
            'iss' => self::ISSUER,
            'sub' => 'f3b9c1e2-0000-4000-8000-000000000001',
            'iat' => self::NOW - 5,
            'exp' => self::NOW + 300,
        ], $overrides);

        return array_filter($claims, static fn ($value): bool => null !== $value);
    }
}
