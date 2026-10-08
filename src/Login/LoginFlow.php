<?php

declare(strict_types=1);

namespace Bannerstop\Keycloak\Login;

use Bannerstop\Keycloak\Exception\HttpException;
use Bannerstop\Keycloak\Exception\InvalidTokenException;
use Bannerstop\Keycloak\Exception\LoginException;
use Bannerstop\Keycloak\KeycloakClient;
use Bannerstop\Keycloak\Policy\IdentityPolicy;

/**
 * The browser login: start() sends the user to Keycloak, finish() handles
 * the callback and returns the verified identity.
 */
final class LoginFlow
{
    private KeycloakClient $client;
    private StateStore $store;

    /** @var IdentityPolicy[] */
    private array $policies;

    /**
     * @param IdentityPolicy[] $policies All of them must allow an identity
     */
    public function __construct(KeycloakClient $client, StateStore $store, array $policies = [])
    {
        $this->client = $client;
        $this->store = $store;
        $this->policies = $policies;
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
    public function finish(array $query): LoginResult
    {
        $state = self::parameter($query, 'state');
        $login = null === $state ? null : $this->store->take($state);
        if (null === $login || $login->isExpired($this->client->now())) {
            throw new LoginException(LoginException::STATE_MISMATCH, 'The callback does not match a pending login.');
        }

        $error = self::parameter($query, 'error');
        if (null !== $error) {
            $reason = 'access_denied' === $error ? LoginException::CANCELLED : LoginException::PROVIDER_ERROR;
            throw new LoginException($reason, sprintf('Keycloak reported "%s".', $error));
        }
        $code = self::parameter($query, 'code');
        if (null === $code) {
            throw new LoginException(LoginException::PROVIDER_ERROR, 'The callback has no authorization code.');
        }

        try {
            $tokens = $this->client->exchangeCode($code, $login);
            $identity = $this->client->getIdentity($tokens, $login->getNonce());
        } catch (HttpException $exception) {
            throw new LoginException(LoginException::PROVIDER_ERROR, 'The code exchange failed: ' . $exception->getMessage(), $exception);
        } catch (InvalidTokenException $exception) {
            throw new LoginException(LoginException::INVALID_TOKEN, 'The tokens failed verification: ' . $exception->getMessage(), $exception);
        }

        foreach ($this->policies as $policy) {
            if (!$policy->allows($identity)) {
                throw new LoginException(LoginException::NOT_ALLOWED, sprintf('%s rejected the identity.', get_class($policy)));
            }
        }

        return new LoginResult($identity, $tokens, $login->getReturnTo());
    }

    /**
     * @param array<string, mixed> $query
     */
    private static function parameter(array $query, string $name): ?string
    {
        return isset($query[$name]) && is_string($query[$name]) && '' !== $query[$name] ? $query[$name] : null;
    }
}
