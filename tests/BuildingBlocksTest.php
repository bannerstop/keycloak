<?php

declare(strict_types=1);

namespace Bannerstop\Keycloak\Tests;

use Bannerstop\Keycloak\Bearer\BearerToken;
use Bannerstop\Keycloak\Exception\ConfigurationException;
use Bannerstop\Keycloak\Identity;
use Bannerstop\Keycloak\KeycloakConfig;
use Bannerstop\Keycloak\Login\RedirectTarget;
use Bannerstop\Keycloak\Policy\EmailDomainPolicy;
use Bannerstop\Keycloak\Role\RoleMapper;
use Bannerstop\Keycloak\Token\Claims;
use Bannerstop\Keycloak\Token\TokenSet;
use PHPUnit\Framework\TestCase;

final class BuildingBlocksTest extends TestCase
{
    public function testConfigDerivesIssuerAndAdminUrl(): void
    {
        $config = KeycloakConfig::fromArray([
            'server_url' => 'https://sso.example.com/',
            'realm' => 'example',
            'client_id' => 'app',
            'client_secret' => '',
        ]);

        self::assertSame('https://sso.example.com/realms/example', $config->getIssuer());
        self::assertSame('https://sso.example.com/admin/realms/example', $config->getAdminUrl());
        self::assertFalse($config->isConfidential(), 'An empty secret means a public client.');
        self::assertSame(['openid', 'email', 'profile'], $config->getScopes());
    }

    public function testConfigKeepsTheSecretOutOfDumps(): void
    {
        $config = new KeycloakConfig('https://sso.example.com', 'example', 'app', 'very-secret');

        self::assertStringNotContainsString('very-secret', print_r($config, true));
    }

    /**
     * @dataProvider invalidConfigs
     *
     * @param array<string, mixed> $options
     */
    public function testConfigRejectsInvalidValues(array $options): void
    {
        $this->expectException(ConfigurationException::class);

        KeycloakConfig::fromArray(array_merge(['server_url' => 'https://sso.example.com', 'realm' => 'example', 'client_id' => 'app'], $options));
    }

    /**
     * @return array<string, array<int, array<string, mixed>>>
     */
    public function invalidConfigs(): array
    {
        return [
            'relative server url' => [['server_url' => 'sso.example.com']],
            'other scheme' => [['server_url' => 'ftp://sso.example.com']],
            'no realm' => [['realm' => '']],
            'symmetric algorithm' => [['allowed_algorithms' => ['HS256']]],
            'none algorithm' => [['allowed_algorithms' => ['none']]],
            'no algorithm' => [['allowed_algorithms' => []]],
            'huge leeway' => [['leeway' => 3600]],
        ];
    }

    public function testTokenSetKeepsTokensOutOfDumps(): void
    {
        $tokens = TokenSet::fromResponse(['access_token' => 'access-secret', 'refresh_token' => 'refresh-secret', 'expires_in' => 60], 1000);

        self::assertSame(1060, $tokens->getExpiresAt());
        self::assertStringNotContainsString('secret', print_r($tokens, true));
        self::assertEquals($tokens, TokenSet::fromArray($tokens->toArray()));
    }

    public function testRoleMapperOnlyGrantsMappedRoles(): void
    {
        $mapper = RoleMapper::fromArray([
            'default_roles' => ['ROLE_USER'],
            'realm_roles' => ['admin' => ['ROLE_ADMIN', 'ROLE_STAFF']],
            'client_roles' => ['app' => ['editor' => 'ROLE_EDITOR'], 'other' => ['editor' => 'ROLE_OTHER']],
            'groups' => ['/staff/it' => ['ROLE_IT', 'ROLE_STAFF']],
        ]);
        $identity = new Identity(new Claims([
            'sub' => 'u1',
            'realm_access' => ['roles' => ['admin', 'offline_access']],
            'resource_access' => ['app' => ['roles' => ['editor']]],
            'groups' => ['/staff/it', '/unmapped'],
        ]));

        self::assertSame(['ROLE_USER', 'ROLE_ADMIN', 'ROLE_STAFF', 'ROLE_EDITOR', 'ROLE_IT'], $mapper->map($identity));
        self::assertSame(['ROLE_USER'], $mapper->map(new Identity(new Claims(['sub' => 'u2']))));
    }

    public function testRoleMapperRejectsBrokenConfig(): void
    {
        $this->expectException(ConfigurationException::class);

        RoleMapper::fromArray(['realm_roles' => ['admin' => [42]]]);
    }

    public function testRoleMapperIsImmutable(): void
    {
        $base = new RoleMapper();
        $base->withRealmRole('admin', ['ROLE_ADMIN']);

        self::assertSame([], $base->map(new Identity(new Claims(['sub' => 'u', 'realm_access' => ['roles' => ['admin']]]))));
    }

    public function testEmailDomainPolicy(): void
    {
        $policy = new EmailDomainPolicy([' Example.com ']);
        $identity = static function (string $email, bool $verified): Identity {
            return new Identity(new Claims(['sub' => 'u', 'email' => $email, 'email_verified' => $verified]));
        };

        self::assertTrue($policy->allows($identity('jane@EXAMPLE.com', true)));
        self::assertFalse($policy->allows($identity('jane@example.com', false)), 'unverified');
        self::assertFalse($policy->allows($identity('jane@sub.example.com', true)), 'subdomain');
        self::assertFalse($policy->allows($identity('jane@example.com.evil.test', true)), 'suffix');
        self::assertFalse($policy->allows($identity('example.com', true)), 'no @');
        self::assertFalse($policy->allows(new Identity(new Claims(['sub' => 'u', 'email_verified' => true]))), 'no e-mail');
        self::assertTrue((new EmailDomainPolicy(['example.com'], false))->allows($identity('jane@example.com', false)));
    }

    public function testIdentityDisplayNameFallbacks(): void
    {
        self::assertSame('Jane Doe', (new Identity(new Claims(['sub' => 'u', 'given_name' => 'Jane', 'family_name' => 'Doe'])))->getDisplayName());
        self::assertSame('jdoe', (new Identity(new Claims(['sub' => 'u', 'preferred_username' => 'jdoe'])))->getDisplayName());
        self::assertSame('u', (new Identity(new Claims(['sub' => 'u'])))->getDisplayName());
        self::assertSame('Jane 0', (new Identity(new Claims(['sub' => 'u', 'given_name' => 'Jane', 'family_name' => '0'])))->getDisplayName());
    }

    /**
     * @dataProvider redirectTargets
     */
    public function testRedirectTargets(?string $target, bool $local): void
    {
        self::assertSame($local, RedirectTarget::isLocal($target));
    }

    /**
     * @return array<string, array{0: string|null, 1: bool}>
     */
    public function redirectTargets(): array
    {
        return [
            'path' => ['/orders?page=2#top', true],
            'root' => ['/', true],
            'null' => [null, false],
            'empty' => ['', false],
            'absolute' => ['https://evil.example/', false],
            'protocol relative' => ['//evil.example/', false],
            'backslash' => ['/\\evil.example', false],
            'relative' => ['orders', false],
            'javascript' => ['javascript:alert(1)', false],
            'newline' => ["/orders\r\nLocation: https://evil.example", false],
            'tab' => ["/\t/evil.example", false],
        ];
    }

    public function testBearerTokenFromHeader(): void
    {
        self::assertSame('abc.def.ghi', BearerToken::fromAuthorizationHeader('Bearer abc.def.ghi'));
        self::assertSame('abc.def.ghi', BearerToken::fromAuthorizationHeader('bearer  abc.def.ghi '));
        self::assertNull(BearerToken::fromAuthorizationHeader('Basic YTpi'));
        self::assertNull(BearerToken::fromAuthorizationHeader('Bearer'));
        self::assertNull(BearerToken::fromAuthorizationHeader('Bearer a b'));
        self::assertNull(BearerToken::fromAuthorizationHeader(null));
    }

    public function testClaimsAccessors(): void
    {
        $claims = new Claims(['aud' => 'app', 'list' => ['a', 1, '', 'b'], 'flag' => 'true', 'n' => 1.0, 'nested' => ['x' => ['y' => 'z']]]);

        self::assertSame(['app'], $claims->getStringList('aud'));
        self::assertSame(['a', 'b'], $claims->getStringList('list'));
        self::assertTrue($claims->getBool('flag'));
        self::assertSame(1, $claims->getInt('n'));
        self::assertSame('z', $claims->getPath(['nested', 'x', 'y']));
        self::assertNull($claims->getPath(['nested', 'missing']));
        self::assertNull($claims->getString('list'));
    }
}
