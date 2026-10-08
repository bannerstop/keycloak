<?php

declare(strict_types=1);

namespace Bannerstop\Keycloak\Tests;

use Bannerstop\Keycloak\Exception\InvalidTokenException;
use Bannerstop\Keycloak\Identity;
use Bannerstop\Keycloak\Login\LoginResult;
use Bannerstop\Keycloak\Session\KeycloakSession;
use Bannerstop\Keycloak\Session\SessionCheck;
use Bannerstop\Keycloak\Session\SessionRevocations;
use Bannerstop\Keycloak\Tests\Fixtures\FakeKeycloak;
use Bannerstop\Keycloak\Token\Claims;
use Bannerstop\Keycloak\Token\TokenSet;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\RequestInterface;
use Symfony\Component\Cache\Adapter\ArrayAdapter;
use Symfony\Component\Cache\Psr16Cache;

final class SessionTest extends TestCase
{
    private const SUBJECT = 'f3b9c1e2-0000-4000-8000-000000000001';
    private const EVENT = 'http://schemas.openid.net/event/backchannel-logout';

    public function testVerifiesALogoutToken(): void
    {
        $realm = new FakeKeycloak();

        $token = $realm->client()->verifyLogoutToken($realm->key->sign(self::logoutClaims()));

        self::assertSame(self::SUBJECT, $token->getSubject());
        self::assertSame('kc-session', $token->getSessionId());
        self::assertSame('logout-1', $token->getTokenId());
    }

    /**
     * @dataProvider invalidLogoutTokens
     *
     * @param array<string, mixed> $claims
     */
    public function testRejectsInvalidLogoutTokens(array $claims, string $message): void
    {
        $realm = new FakeKeycloak();

        $this->expectException(InvalidTokenException::class);
        $this->expectExceptionMessage($message);

        $realm->client()->verifyLogoutToken($realm->key->sign(self::logoutClaims($claims)));
    }

    /**
     * @return array<string, array{0: array<string, mixed>, 1: string}>
     */
    public function invalidLogoutTokens(): array
    {
        return [
            'no events' => [['events' => null], 'not a back-channel logout token'],
            'other event' => [['events' => ['http://example.com/other' => []]], 'not a back-channel logout token'],
            'nonce' => [['nonce' => 'n'], 'must not carry a nonce'],
            'other client' => [['aud' => 'other-app'], 'another client'],
            'no subject and no session' => [['sub' => null, 'sid' => null], 'neither a user nor a session'],
            'no jti' => [['jti' => null], 'no jti'],
            'other issuer' => [['iss' => 'https://evil.example/realms/example'], 'another issuer'],
            'expired' => [['exp' => FakeKeycloak::NOW - 120], 'expired'],
            'id token' => [['typ' => 'ID'], 'type'],
        ];
    }

    public function testAnIdTokenIsNoLogoutToken(): void
    {
        $realm = new FakeKeycloak();

        $this->expectException(InvalidTokenException::class);

        $realm->client()->verifyLogoutToken($realm->key->sign(FakeKeycloak::idClaims(['typ' => null, 'sid' => 'kc-session'])));
    }

    public function testRevocationsBySessionAndBySubject(): void
    {
        $revocations = new SessionRevocations(new Psr16Cache(new ArrayAdapter()), 3600);
        $realm = new FakeKeycloak();
        $mine = self::session('kc-session', 1000);
        $other = self::session('other-session', 1000);

        self::assertTrue($revocations->revoke($realm->client()->verifyLogoutToken($realm->key->sign(self::logoutClaims()))));
        self::assertTrue($revocations->isRevoked($mine));
        self::assertFalse($revocations->isRevoked($other));

        // Without sid, every session of the user that started before the token ends.
        self::assertTrue($revocations->revoke($realm->client()->verifyLogoutToken($realm->key->sign(self::logoutClaims(['sid' => null, 'jti' => 'logout-2', 'iat' => 2000])))));
        self::assertTrue($revocations->isRevoked(self::session('another', 1999)));
        self::assertFalse($revocations->isRevoked(self::session('a-later-one', 2001)));
    }

    public function testRejectsReplayedLogoutTokens(): void
    {
        $revocations = new SessionRevocations(new Psr16Cache(new ArrayAdapter()), 3600);
        $realm = new FakeKeycloak();
        $token = $realm->client()->verifyLogoutToken($realm->key->sign(self::logoutClaims()));

        self::assertTrue($revocations->revoke($token));
        self::assertFalse($revocations->revoke($token));
    }

    public function testSessionCheckEndsRevokedSessions(): void
    {
        $realm = new FakeKeycloak();
        $revocations = new SessionRevocations(new Psr16Cache(new ArrayAdapter()), 3600);
        $revocations->revoke($realm->client()->verifyLogoutToken($realm->key->sign(self::logoutClaims())));

        self::assertNull((new SessionCheck($realm->client(), $revocations))->check(self::session('kc-session', FakeKeycloak::NOW)));
    }

    public function testSessionCheckRefreshesOnlyAfterTheInterval(): void
    {
        $realm = new FakeKeycloak();
        $realm->http->on('POST', FakeKeycloak::TOKEN_ENDPOINT, static function (RequestInterface $request): array {
            parse_str((string) $request->getBody(), $body);
            self::assertSame(['grant_type' => 'refresh_token', 'refresh_token' => 'refresh-1'], $body);

            return [200, ['access_token' => 'access-2', 'expires_in' => 300, 'refresh_token' => 'refresh-2']];
        });
        $check = new SessionCheck($realm->client(), null, 60);
        $session = self::session('kc-session', FakeKeycloak::NOW - 30);

        self::assertSame($session, $check->check($session), 'Checked 30 s ago: nothing to do.');
        self::assertCount(0, $realm->http->requestsTo('POST', FakeKeycloak::TOKEN_ENDPOINT));

        $realm->clock->time += 60;
        $refreshed = $check->check($session);

        self::assertNotNull($refreshed);
        self::assertSame('refresh-2', $refreshed->getTokens()->getRefreshToken());
        self::assertSame('id-token', $refreshed->getTokens()->getIdToken(), 'The ID token survives a refresh without one.');
        self::assertSame($realm->clock->time, $refreshed->getCheckedAt());
    }

    public function testSessionCheckEndsSessionsKeycloakRefuses(): void
    {
        $realm = new FakeKeycloak();
        $realm->http->on('POST', FakeKeycloak::TOKEN_ENDPOINT, [400, ['error' => 'invalid_grant']]);
        $realm->clock->time += 3600;

        self::assertNull((new SessionCheck($realm->client(), null, 60))->check(self::session('kc-session', FakeKeycloak::NOW)));
    }

    public function testSessionCheckKeepsSessionsWhileKeycloakIsDown(): void
    {
        $realm = new FakeKeycloak();
        $realm->http->on('POST', FakeKeycloak::TOKEN_ENDPOINT, [503, []]);
        $realm->clock->time += 3600;

        $kept = (new SessionCheck($realm->client(), null, 60))->check(self::session('kc-session', FakeKeycloak::NOW));

        self::assertNotNull($kept);
        self::assertSame($realm->clock->time, $kept->getCheckedAt(), 'The next check waits for the interval again.');
    }

    public function testSessionRoundTrip(): void
    {
        $identity = new Identity(new Claims(['sub' => self::SUBJECT, 'sid' => 'kc-session']));
        $session = KeycloakSession::fromLogin(new LoginResult($identity, new TokenSet('a', 100, 'r', 200, 'i'), null), 50);

        self::assertEquals($session, KeycloakSession::fromArray($session->toArray()));
        self::assertSame('kc-session', $session->getSessionId());
        self::assertNull(KeycloakSession::fromArray(['subject' => 'x']));
        self::assertStringNotContainsString('refresh', print_r($session, true));
    }

    private static function session(string $sessionId, int $checkedAt): KeycloakSession
    {
        return new KeycloakSession(self::SUBJECT, $sessionId, new TokenSet('access-1', null, 'refresh-1', null, 'id-token'), $checkedAt, $checkedAt);
    }

    /**
     * @param array<string, mixed> $overrides null removes a claim
     *
     * @return array<string, mixed>
     */
    private static function logoutClaims(array $overrides = []): array
    {
        $claims = array_merge([
            'iss' => FakeKeycloak::ISSUER,
            'aud' => 'app',
            'sub' => self::SUBJECT,
            'sid' => 'kc-session',
            'iat' => FakeKeycloak::NOW - 5,
            'exp' => FakeKeycloak::NOW + 300,
            'jti' => 'logout-1',
            'typ' => 'Logout',
            'events' => [self::EVENT => new \stdClass()],
        ], $overrides);

        return array_filter($claims, static function ($value): bool {
            return null !== $value;
        });
    }
}
