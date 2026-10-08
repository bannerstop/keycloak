<?php

declare(strict_types=1);

namespace Bannerstop\Keycloak\Tests;

use Bannerstop\Keycloak\Exception\InvalidTokenException;
use Bannerstop\Keycloak\Support\Base64Url;
use Bannerstop\Keycloak\Tests\Fixtures\FakeKeycloak;
use Bannerstop\Keycloak\Tests\Fixtures\TestKey;
use Bannerstop\Keycloak\Token\TokenSet;
use PHPUnit\Framework\TestCase;

final class TokenVerificationTest extends TestCase
{
    public function testAcceptsAValidAccessToken(): void
    {
        $realm = new FakeKeycloak();
        $identity = $realm->client()->verifyAccessToken($realm->key->sign(FakeKeycloak::accessClaims()), 'api');

        self::assertSame('f3b9c1e2-0000-4000-8000-000000000001', $identity->getSubject());
        self::assertSame(['admin', 'offline_access'], $identity->getRealmRoles());
        self::assertSame(['editor'], $identity->getClientRoles('app'));
        self::assertSame(['/staff/it'], $identity->getGroups());
    }

    /**
     * @dataProvider ellipticCurves
     */
    public function testVerifiesEcdsaSignatures(string $curve, string $algorithm): void
    {
        $realm = new FakeKeycloak(TestKey::ec($curve, $algorithm), [$algorithm]);

        $identity = $realm->client()->verifyAccessToken($realm->key->sign(FakeKeycloak::accessClaims()), 'api');

        self::assertSame('f3b9c1e2-0000-4000-8000-000000000001', $identity->getSubject());
    }

    /**
     * @return array<string, string[]>
     */
    public function ellipticCurves(): array
    {
        return [
            'P-256' => ['prime256v1', 'ES256'],
            'P-384' => ['secp384r1', 'ES384'],
            'P-521' => ['secp521r1', 'ES512'],
        ];
    }

    /**
     * @dataProvider invalidAccessTokens
     *
     * @param array<string, mixed> $claims
     */
    public function testRejectsInvalidAccessTokens(array $claims, string $message): void
    {
        $realm = new FakeKeycloak();

        $this->expectException(InvalidTokenException::class);
        $this->expectExceptionMessage($message);

        $realm->client()->verifyAccessToken($realm->key->sign(FakeKeycloak::accessClaims($claims)), 'api');
    }

    /**
     * @return array<string, array{0: array<string, mixed>, 1: string}>
     */
    public function invalidAccessTokens(): array
    {
        return [
            'other issuer' => [['iss' => 'https://sso.example.com/realms/other'], 'another issuer'],
            'other audience' => [['aud' => 'account'], 'audience'],
            'expired' => [['exp' => FakeKeycloak::NOW - 31], 'expired'],
            'no expiry' => [['exp' => null], 'no expiry'],
            'not yet valid' => [['nbf' => FakeKeycloak::NOW + 60], 'not valid yet'],
            'issued in the future' => [['iat' => FakeKeycloak::NOW + 60], 'future'],
            'id token as bearer' => [['typ' => 'ID'], 'type'],
            'refresh token as bearer' => [['typ' => 'Refresh'], 'type'],
            'no subject' => [['sub' => null], 'subject'],
        ];
    }

    public function testToleratesClockSkewWithinTheLeeway(): void
    {
        $realm = new FakeKeycloak();
        $token = $realm->key->sign(FakeKeycloak::accessClaims(['exp' => FakeKeycloak::NOW - 20, 'nbf' => FakeKeycloak::NOW + 20]));

        self::assertSame('f3b9c1e2-0000-4000-8000-000000000001', $realm->client()->verifyAccessToken($token, 'api')->getSubject());
    }

    public function testRejectsUnsignedTokens(): void
    {
        $realm = new FakeKeycloak();
        $token = Base64Url::encode('{"alg":"none"}') . '.' . Base64Url::encode((string) json_encode(FakeKeycloak::accessClaims())) . '.';

        $this->expectException(InvalidTokenException::class);

        $realm->client()->verifyAccessToken($token, 'api');
    }

    public function testRejectsSymmetricAlgorithmsEvenWithThePublicKeyAsSecret(): void
    {
        $realm = new FakeKeycloak();
        $input = Base64Url::encode('{"alg":"HS256","kid":"rsa-key"}') . '.' . Base64Url::encode((string) json_encode(FakeKeycloak::accessClaims()));
        $token = $input . '.' . Base64Url::encode(hash_hmac('sha256', $input, (string) json_encode($realm->key->jwk()), true));

        $this->expectException(InvalidTokenException::class);
        $this->expectExceptionMessage('"HS256" is not allowed');

        $realm->client()->verifyAccessToken($token, 'api');
    }

    public function testRejectsAlgorithmsThatAreNotAllowed(): void
    {
        $realm = new FakeKeycloak(TestKey::ec());

        $this->expectException(InvalidTokenException::class);
        $this->expectExceptionMessage('"ES256" is not allowed');

        $realm->client()->verifyAccessToken($realm->key->sign(FakeKeycloak::accessClaims()), 'api');
    }

    public function testRejectsATamperedPayload(): void
    {
        $realm = new FakeKeycloak();
        $parts = explode('.', $realm->key->sign(FakeKeycloak::accessClaims()));
        $parts[1] = Base64Url::encode((string) json_encode(FakeKeycloak::accessClaims(['realm_access' => ['roles' => ['superuser']]])));

        $this->expectException(InvalidTokenException::class);
        $this->expectExceptionMessage('signature is invalid');

        $realm->client()->verifyAccessToken(implode('.', $parts), 'api');
    }

    public function testRejectsTokensOfAnotherKey(): void
    {
        $realm = new FakeKeycloak();
        $foreign = TestKey::rsa('rsa-key');

        $this->expectException(InvalidTokenException::class);
        $this->expectExceptionMessage('signature is invalid');

        $realm->client()->verifyAccessToken($foreign->sign(FakeKeycloak::accessClaims()), 'api');
    }

    public function testRejectsCriticalHeaders(): void
    {
        $realm = new FakeKeycloak();

        $this->expectException(InvalidTokenException::class);
        $this->expectExceptionMessage('critical');

        $realm->client()->verifyAccessToken($realm->key->sign(FakeKeycloak::accessClaims(), ['crit' => ['exp']]), 'api');
    }

    public function testRejectsMalformedTokens(): void
    {
        $realm = new FakeKeycloak();
        foreach (['', 'abc', 'a.b', 'a.b.c', '!!.!!.!!', str_repeat('a', 70000)] as $token) {
            try {
                $realm->client()->verifyAccessToken($token, 'api');
                self::fail(sprintf('"%s" was accepted.', substr($token, 0, 20)));
            } catch (InvalidTokenException $exception) {
                self::assertNotSame('', $exception->getMessage());
            }
        }
    }

    public function testReloadsTheKeySetAfterAKeyRotation(): void
    {
        $realm = new FakeKeycloak();
        $client = $realm->client();
        $client->verifyAccessToken($realm->key->sign(FakeKeycloak::accessClaims()), 'api');

        $rotated = TestKey::rsa('rotated-key');
        $realm->publishKeys([$realm->key->jwk(), $rotated->jwk()]);
        $realm->clock->time += 120;

        $client->verifyAccessToken($rotated->sign(FakeKeycloak::accessClaims(['exp' => $realm->clock->time + 300])), 'api');

        self::assertCount(2, $realm->http->requestsTo('GET', FakeKeycloak::JWKS_URI));
    }

    public function testUnknownKeyIdsDoNotHammerKeycloak(): void
    {
        $realm = new FakeKeycloak();
        $client = $realm->client();
        $client->verifyAccessToken($realm->key->sign(FakeKeycloak::accessClaims()), 'api');

        $forged = TestKey::rsa('forged');
        for ($i = 0; $i < 5; ++$i) {
            try {
                $client->verifyAccessToken($forged->sign(FakeKeycloak::accessClaims()), 'api');
                self::fail('A token of an unknown key was accepted.');
            } catch (InvalidTokenException $exception) {
                self::assertStringContainsString('unknown key', $exception->getMessage());
            }
        }

        self::assertCount(1, $realm->http->requestsTo('GET', FakeKeycloak::JWKS_URI));
    }

    public function testIdTokenChecks(): void
    {
        $realm = new FakeKeycloak();
        $cases = [
            'nonce of another login' => [['nonce' => 'other'], 'another login'],
            'no nonce' => [['nonce' => null], 'another login'],
            'other client' => [['aud' => 'other-app', 'azp' => 'other-app'], 'another client'],
            'other authorized party' => [['aud' => ['app', 'other-app'], 'azp' => 'other-app'], 'authorized party'],
            'no iat' => [['iat' => null], 'iat'],
            'access token as id token' => [['typ' => 'Bearer'], 'type'],
        ];
        foreach ($cases as $case => [$claims, $message]) {
            $tokens = new TokenSet('opaque', null, null, null, $realm->key->sign(FakeKeycloak::idClaims($claims)));
            try {
                $realm->client()->getIdentity($tokens, 'the-nonce');
                self::fail(sprintf('Case "%s" was accepted.', $case));
            } catch (InvalidTokenException $exception) {
                self::assertStringContainsString($message, $exception->getMessage(), $case);
            }
        }
    }

    public function testMergesRolesFromTheAccessToken(): void
    {
        $realm = new FakeKeycloak();
        $tokens = new TokenSet($realm->key->sign(FakeKeycloak::accessClaims()), null, null, null, $realm->key->sign(FakeKeycloak::idClaims()));

        $identity = $realm->client()->getIdentity($tokens, 'the-nonce');

        self::assertSame('jane.doe@example.com', $identity->getEmail());
        self::assertSame('Jane Doe', $identity->getDisplayName());
        self::assertSame(['admin', 'offline_access'], $identity->getRealmRoles());
        self::assertSame('app', $identity->getClaims()->getString('aud'), 'ID token claims win');
    }

    public function testRejectsAnAccessTokenOfAnotherUser(): void
    {
        $realm = new FakeKeycloak();
        $tokens = new TokenSet(
            $realm->key->sign(FakeKeycloak::accessClaims(['sub' => 'someone-else'])),
            null,
            null,
            null,
            $realm->key->sign(FakeKeycloak::idClaims())
        );

        $this->expectException(InvalidTokenException::class);
        $this->expectExceptionMessage('different users');

        $realm->client()->getIdentity($tokens, 'the-nonce');
    }

    public function testRejectsAnAccessTokenOfAnotherClient(): void
    {
        $realm = new FakeKeycloak();
        $tokens = new TokenSet(
            $realm->key->sign(FakeKeycloak::accessClaims(['azp' => 'other-app'])),
            null,
            null,
            null,
            $realm->key->sign(FakeKeycloak::idClaims())
        );

        $this->expectException(InvalidTokenException::class);
        $this->expectExceptionMessage('another client');

        $realm->client()->getIdentity($tokens, 'the-nonce');
    }

    public function testTokensStayOutOfStackTraces(): void
    {
        $realm = new FakeKeycloak();
        $token = $realm->key->sign(FakeKeycloak::accessClaims(['aud' => 'other']));

        try {
            $realm->client()->verifyAccessToken($token, 'api');
            self::fail('The token was accepted.');
        } catch (InvalidTokenException $exception) {
            self::assertStringNotContainsString(substr($token, -20), $exception->getTraceAsString());
        }
    }
}
