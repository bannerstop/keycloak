<?php

declare(strict_types=1);

namespace Bannerstop\Keycloak\Session;

use Bannerstop\Keycloak\Token\LogoutToken;
use Psr\SimpleCache\CacheInterface;

/**
 * Keycloak sessions ended through back-channel logout. Keycloak's call comes
 * without the user's session, so the ending is recorded here and SessionCheck
 * ends the matching application sessions on their next request.
 *
 * The cache must be shared by all web servers of the application. Entries
 * should live as long as an idle application session can: a session idle for
 * longer has expired on its own anyway.
 */
final class SessionRevocations
{
    private const PREFIX = 'bannerstop_keycloak.revoked.';

    private CacheInterface $cache;
    private int $ttl;

    public function __construct(CacheInterface $cache, int $ttl)
    {
        $this->cache = $cache;
        $this->ttl = $ttl;
    }

    /**
     * Records a logout token. Returns false for a token that was seen before,
     * which the caller must answer with an error (replay).
     */
    public function revoke(LogoutToken $token): bool
    {
        $tokenKey = self::PREFIX . 'jti.' . sha1($token->getTokenId());
        // PSR-16 has no atomic "add"; a replay racing the original within
        // milliseconds can only record the same ending twice.
        if ($this->cache->has($tokenKey)) {
            return false;
        }
        $this->cache->set($tokenKey, true, $this->ttl);

        $sessionId = $token->getSessionId();
        if (null !== $sessionId) {
            $this->cache->set(self::PREFIX . 'sid.' . sha1($sessionId), true, $this->ttl);
        } else {
            $this->cache->set(self::PREFIX . 'sub.' . sha1((string) $token->getSubject()), $token->getIssuedAt(), $this->ttl);
        }

        return true;
    }

    /**
     * Whether Keycloak ended this session: by its session id, or by ending
     * every session of the user that started before the logout token.
     */
    public function isRevoked(KeycloakSession $session): bool
    {
        $sessionId = $session->getSessionId();
        if (null !== $sessionId && true === $this->cache->get(self::PREFIX . 'sid.' . sha1($sessionId))) {
            return true;
        }
        $endedAt = $this->cache->get(self::PREFIX . 'sub.' . sha1($session->getSubject()));

        return is_int($endedAt) && $session->getLoggedInAt() <= $endedAt;
    }
}
