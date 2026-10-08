<?php

declare(strict_types=1);

namespace Bannerstop\Keycloak\Login;

use Bannerstop\Keycloak\Exception\HttpException;
use Bannerstop\Keycloak\Exception\InvalidTokenException;
use Bannerstop\Keycloak\Exception\LoginException;
use Bannerstop\Keycloak\Exception\LoginFailure;
use Bannerstop\Keycloak\KeycloakClient;
use Bannerstop\Keycloak\Policy\IdentityPolicy;

/**
 * The browser login: start() sends the user to Keycloak, finish() handles
 * the callback and returns the verified identity.
 */
final readonly class LoginFlow
{
    /**
     * @param IdentityPolicy[] $policies All of them must allow an identity
     */
    public function __construct(
        private KeycloakClient $client,
        private StateStore $store,
        private array $policies = [],
    ) {
    }

    /**
     * Remembers a new pending login and returns the Keycloak URL to redirect to.
     *
     * @param string                    $redirectUri Absolute URL of the callback, registered as redirect URI in Keycloak
     * @param string|null               $returnTo    Where to send the user after the login
     * @param array<string, string|int> $parameters  See KeycloakClient::getAuthorizationUrl()
     */
    public function start(string $redirectUri, ?string $returnTo = null, array $parameters = []): string
    {
        $login = PendingLogin::start($redirectUri, $returnTo, $this->client->now());
        $this->store->save($login);

        return $this->client->getAuthorizationUrl($login, $parameters);
    }

    /**
     * Handles the callback request.
     *
     * @param array<string, mixed> $query The query parameters of the callback ($_GET)
     *
     * @throws LoginException
     */
    public function finish(#[\SensitiveParameter] array $query): LoginResult
    {
        $state = self::parameter($query, 'state');
        $login = null === $state ? null : $this->store->take($state);
        if (null === $login || $login->isExpired($this->client->now())) {
            throw new LoginException(LoginFailure::StateMismatch, 'The callback does not match a pending login.');
        }
        $this->checkIssuer($query);

        $error = self::parameter($query, 'error');
        if (null !== $error) {
            $reason = 'access_denied' === $error ? LoginFailure::Cancelled : LoginFailure::ProviderError;
            throw new LoginException($reason, sprintf('Keycloak reported "%s".', $error));
        }
        $code = self::parameter($query, 'code');
        if (null === $code) {
            throw new LoginException(LoginFailure::ProviderError, 'The callback has no authorization code.');
        }

        try {
            $tokens = $this->client->exchangeCode($code, $login);
            $identity = $this->client->getIdentity($tokens, $login->getNonce());
        } catch (HttpException $exception) {
            throw new LoginException(LoginFailure::ProviderError, 'The code exchange failed: ' . $exception->getMessage(), $exception);
        } catch (InvalidTokenException $exception) {
            throw new LoginException(LoginFailure::InvalidToken, 'The tokens failed verification: ' . $exception->getMessage(), $exception);
        }

        $rejecting = array_find($this->policies, static fn (IdentityPolicy $policy): bool => !$policy->allows($identity));
        if (null !== $rejecting) {
            throw new LoginException(LoginFailure::NotAllowed, sprintf('%s rejected the identity.', $rejecting::class));
        }

        return new LoginResult($identity, $tokens, $login->getReturnTo());
    }

    /**
     * Against mix-up attacks (RFC 9207): the callback must name the issuer of
     * this client's realm, and must name one at all if the provider says it
     * always does. Applies to error responses too.
     *
     * @param array<string, mixed> $query
     *
     * @throws LoginException
     */
    private function checkIssuer(#[\SensitiveParameter] array $query): void
    {
        try {
            $required = $this->client->getMetadata()->isIssuerParameterSupported();
        } catch (HttpException $exception) {
            throw new LoginException(LoginFailure::ProviderError, 'The discovery document is unavailable: ' . $exception->getMessage(), $exception);
        }
        $issuer = self::parameter($query, 'iss');
        if (null === $issuer && $required) {
            throw new LoginException(LoginFailure::ProviderError, 'The callback names no issuer, although the provider always sends one (RFC 9207).');
        }
        if (null !== $issuer && $issuer !== $this->client->getConfig()->getIssuer()) {
            throw new LoginException(LoginFailure::ProviderError, 'The callback was issued by another provider (RFC 9207).');
        }
    }

    /**
     * @param array<string, mixed> $query
     */
    private static function parameter(#[\SensitiveParameter] array $query, string $name): ?string
    {
        return isset($query[$name]) && is_string($query[$name]) && '' !== $query[$name] ? $query[$name] : null;
    }
}
