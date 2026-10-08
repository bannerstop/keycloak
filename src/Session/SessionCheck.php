<?php

declare(strict_types=1);

namespace Bannerstop\Keycloak\Session;

use Bannerstop\Keycloak\Exception\HttpException;
use Bannerstop\Keycloak\KeycloakClient;

/**
 * Keeps an application session from outliving its Keycloak session.
 *
 * A session Keycloak ended through back-channel logout ends at once. Every
 * $interval seconds the refresh token is redeemed; once Keycloak refuses it
 * (logout elsewhere, user disabled, SSO session expired), the session ends
 * too. If Keycloak cannot be reached, the session is kept: an outage must not
 * sign everybody out.
 */
final class SessionCheck
{
    private KeycloakClient $client;
    private ?SessionRevocations $revocations;
    private int $interval;

    /**
     * @param int $interval Seconds between refresh checks, 0 to only honour back-channel logouts
     */
    public function __construct(KeycloakClient $client, ?SessionRevocations $revocations = null, int $interval = 0)
    {
        $this->client = $client;
        $this->revocations = $revocations;
        $this->interval = $interval;
    }

    /**
     * Returns the session to store (possibly with fresh tokens), or null if
     * it has ended and the application must log the user out.
     */
    public function check(KeycloakSession $session): ?KeycloakSession
    {
        if (null !== $this->revocations && $this->revocations->isRevoked($session)) {
            return null;
        }
        $now = $this->client->now();
        if ($this->interval <= 0 || $session->getCheckedAt() > $now - $this->interval) {
            return $session;
        }
        $refreshToken = $session->getTokens()->getRefreshToken();
        if (null === $refreshToken) {
            return null;
        }

        try {
            return $session->withRefreshedTokens($this->client->refresh($refreshToken), $now);
        } catch (HttpException $exception) {
            // 400/401 = Keycloak refused the token; anything else means Keycloak is not reachable or broken.
            return in_array($exception->getStatusCode(), [400, 401], true) ? null : $session->withCheckedAt($now);
        }
    }
}
