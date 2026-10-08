<?php

declare(strict_types=1);

namespace Bannerstop\Keycloak\Tests;

use Bannerstop\Keycloak\Exception\LoginException;
use Bannerstop\Keycloak\Exception\LoginFailure;
use Bannerstop\Keycloak\Login\LoginFlow;
use Bannerstop\Keycloak\Login\PendingLogin;
use Bannerstop\Keycloak\Login\StateStore;
use Bannerstop\Keycloak\Policy\EmailDomainPolicy;
use Bannerstop\Keycloak\Tests\Fixtures\FakeKeycloak;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\RequestInterface;

final class LoginFlowTest extends TestCase
{
    private const string CALLBACK = 'https://app.example.com/login/callback';

    private FakeKeycloak $realm;
    private StateStore $store;

    #[\Override]
    protected function setUp(): void
    {
        $this->realm = new FakeKeycloak();
        $this->store = new class() implements StateStore {
            /** @var array<string, PendingLogin> */
            public array $logins = [];

            #[\Override]
            public function save(PendingLogin $login): void
            {
                $this->logins[$login->getState()] = $login;
            }

            #[\Override]
            public function take(string $state): ?PendingLogin
            {
                $login = $this->logins[$state] ?? null;
                unset($this->logins[$state]);

                return $login;
            }
        };
    }

    public function testStartRedirectsToKeycloakWithPkce(): void
    {
        $url = $this->flow()->start(self::CALLBACK, '/orders', ['kc_idp_hint' => 'ad']);

        self::assertStringStartsWith(FakeKeycloak::ISSUER . '/protocol/openid-connect/auth?', $url);
        parse_str((string) parse_url($url, PHP_URL_QUERY), $query);
        $login = $this->store->take((string) $query['state']);
        self::assertNotNull($login);
        self::assertSame('code', $query['response_type']);
        self::assertSame('app', $query['client_id']);
        self::assertSame(self::CALLBACK, $query['redirect_uri']);
        self::assertSame('openid email profile', $query['scope']);
        self::assertSame($login->getNonce(), $query['nonce']);
        self::assertSame('S256', $query['code_challenge_method']);
        self::assertSame($login->getCodeChallenge(), $query['code_challenge']);
        self::assertSame('ad', $query['kc_idp_hint']);
        self::assertSame('/orders', $login->getReturnTo());
        self::assertGreaterThanOrEqual(43, strlen($login->getCodeVerifier()));
    }

    public function testStartRejectsUnknownParameters(): void
    {
        $this->expectException(\InvalidArgumentException::class);

        (void) $this->flow()->start(self::CALLBACK, null, ['redirect_uri' => 'https://evil.example']);
    }

    public function testFinishReturnsTheVerifiedIdentity(): void
    {
        $state = $this->startLogin();
        $nonce = $this->store->logins[$state]->getNonce();
        $verifier = $this->store->logins[$state]->getCodeVerifier();
        $this->realm->http->on('POST', FakeKeycloak::TOKEN_ENDPOINT, function (RequestInterface $request) use ($nonce, $verifier): array {
            parse_str((string) $request->getBody(), $body);
            self::assertSame('authorization_code', $body['grant_type']);
            self::assertSame('the-code', $body['code']);
            self::assertSame($verifier, $body['code_verifier']);
            self::assertSame(self::CALLBACK, $body['redirect_uri']);
            self::assertArrayNotHasKey('client_secret', $body, 'The secret goes into the Authorization header.');
            self::assertSame('Basic ' . base64_encode('app:secret'), $request->getHeaderLine('Authorization'));

            return [200, $this->tokenResponse($nonce)];
        });

        $result = $this->flow()->finish(['state' => $state, 'code' => 'the-code', 'session_state' => 'x']);

        self::assertSame('jane.doe@example.com', $result->getIdentity()->getEmail());
        self::assertSame(['editor'], $result->getIdentity()->getClientRoles('app'));
        self::assertSame('/orders', $result->getReturnTo());
        self::assertSame(FakeKeycloak::NOW + 300, $result->getTokens()->getExpiresAt());
        self::assertSame('refresh', $result->getTokens()->getRefreshToken());
    }

    public function testACallbackWorksOnlyOnce(): void
    {
        $state = $this->startLogin();
        $nonce = $this->store->logins[$state]->getNonce();
        $this->realm->http->on('POST', FakeKeycloak::TOKEN_ENDPOINT, [200, $this->tokenResponse($nonce)]);
        $this->flow()->finish(['state' => $state, 'code' => 'the-code']);

        $this->assertLoginFails(LoginFailure::StateMismatch, function () use ($state): void {
            $this->flow()->finish(['state' => $state, 'code' => 'the-code']);
        });
    }

    public function testRejectsAnUnknownState(): void
    {
        $this->startLogin();

        $this->assertLoginFails(LoginFailure::StateMismatch, function (): void {
            $this->flow()->finish(['state' => 'forged', 'code' => 'the-code']);
        });
    }

    public function testRejectsAMissingState(): void
    {
        $this->assertLoginFails(LoginFailure::StateMismatch, function (): void {
            $this->flow()->finish(['code' => 'the-code']);
        });
    }

    public function testRejectsAnExpiredLogin(): void
    {
        $state = $this->startLogin();
        $this->realm->clock->time += 601;

        $this->assertLoginFails(LoginFailure::StateMismatch, function () use ($state): void {
            $this->flow()->finish(['state' => $state, 'code' => 'the-code']);
        });
    }

    public function testAcceptsTheIssuerParameter(): void
    {
        $this->realm->sendsIssuerParameter = true;
        $state = $this->startLogin();
        $nonce = $this->store->logins[$state]->getNonce();
        $this->realm->http->on('POST', FakeKeycloak::TOKEN_ENDPOINT, [200, $this->tokenResponse($nonce)]);

        $result = $this->flow()->finish(['state' => $state, 'code' => 'the-code', 'iss' => FakeKeycloak::ISSUER]);

        self::assertSame('jdoe', $result->getIdentity()->getUsername());
    }

    public function testRejectsACallbackOfAnotherIssuer(): void
    {
        $state = $this->startLogin();

        $this->assertLoginFails(LoginFailure::ProviderError, function () use ($state): void {
            $this->flow()->finish(['state' => $state, 'code' => 'the-code', 'iss' => 'https://evil.example/realms/example']);
        });
        self::assertCount(0, $this->realm->http->requestsTo('POST', FakeKeycloak::TOKEN_ENDPOINT), 'The code is never redeemed.');
    }

    public function testRejectsACallbackWithoutIssuerWhenTheProviderAlwaysSendsOne(): void
    {
        $this->realm->sendsIssuerParameter = true;
        $state = $this->startLogin();

        $this->assertLoginFails(LoginFailure::ProviderError, function () use ($state): void {
            $this->flow()->finish(['state' => $state, 'code' => 'the-code']);
        });
    }

    public function testChecksTheIssuerOfErrorResponsesToo(): void
    {
        $state = $this->startLogin();

        $this->assertLoginFails(LoginFailure::ProviderError, function () use ($state): void {
            $this->flow()->finish(['state' => $state, 'error' => 'access_denied', 'iss' => 'https://evil.example/realms/example']);
        });
    }

    public function testReportsACancelledLogin(): void
    {
        $state = $this->startLogin();

        $this->assertLoginFails(LoginFailure::Cancelled, function () use ($state): void {
            $this->flow()->finish(['state' => $state, 'error' => 'access_denied']);
        });
    }

    public function testReportsAFailedCodeExchange(): void
    {
        $state = $this->startLogin();
        $this->realm->http->on('POST', FakeKeycloak::TOKEN_ENDPOINT, [400, ['error' => 'invalid_grant']]);

        $this->assertLoginFails(LoginFailure::ProviderError, function () use ($state): void {
            $this->flow()->finish(['state' => $state, 'code' => 'the-code']);
        });
    }

    public function testReportsTokensThatFailVerification(): void
    {
        $state = $this->startLogin();
        $this->realm->http->on('POST', FakeKeycloak::TOKEN_ENDPOINT, [200, $this->tokenResponse('another-nonce')]);

        $this->assertLoginFails(LoginFailure::InvalidToken, function () use ($state): void {
            $this->flow()->finish(['state' => $state, 'code' => 'the-code']);
        });
    }

    public function testAppliesPolicies(): void
    {
        $state = $this->startLogin();
        $nonce = $this->store->logins[$state]->getNonce();
        $this->realm->http->on('POST', FakeKeycloak::TOKEN_ENDPOINT, [200, $this->tokenResponse($nonce)]);
        $flow = new LoginFlow($this->realm->client(), $this->store, [new EmailDomainPolicy(['example.org'])]);

        $this->assertLoginFails(LoginFailure::NotAllowed, function () use ($flow, $state): void {
            $flow->finish(['state' => $state, 'code' => 'the-code']);
        });
    }

    public function testPublicClientsSendTheirIdInsteadOfASecret(): void
    {
        $this->realm = new FakeKeycloak(null, ['RS256'], null);
        $state = $this->startLogin();
        $nonce = $this->store->logins[$state]->getNonce();
        $this->realm->http->on('POST', FakeKeycloak::TOKEN_ENDPOINT, function (RequestInterface $request) use ($nonce): array {
            parse_str((string) $request->getBody(), $body);
            self::assertSame('app', $body['client_id']);
            self::assertSame('', $request->getHeaderLine('Authorization'));

            return [200, $this->tokenResponse($nonce)];
        });

        self::assertSame('jdoe', $this->flow()->finish(['state' => $state, 'code' => 'c'])->getIdentity()->getUsername());
    }

    private function flow(): LoginFlow
    {
        return new LoginFlow($this->realm->client(), $this->store);
    }

    private function startLogin(): string
    {
        parse_str((string) parse_url($this->flow()->start(self::CALLBACK, '/orders'), PHP_URL_QUERY), $query);

        return (string) $query['state'];
    }

    /**
     * @return array<string, mixed>
     */
    private function tokenResponse(string $nonce): array
    {
        return [
            'access_token' => $this->realm->key->sign(FakeKeycloak::accessClaims()),
            'expires_in' => 300,
            'refresh_token' => 'refresh',
            'refresh_expires_in' => 1800,
            'id_token' => $this->realm->key->sign(FakeKeycloak::idClaims(['nonce' => $nonce])),
            'token_type' => 'Bearer',
        ];
    }

    private function assertLoginFails(LoginFailure $reason, callable $finish): void
    {
        try {
            $finish();
        } catch (LoginException $exception) {
            self::assertSame($reason, $exception->getReason(), $exception->getMessage());

            return;
        }
        self::fail(sprintf('The login did not fail with "%s".', $reason->value));
    }
}
