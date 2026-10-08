<?php

declare(strict_types=1);

namespace Bannerstop\Keycloak\Login;

/**
 * StateStore on top of $_SESSION, for applications without a framework.
 * The session must be started before the store is used.
 */
final readonly class NativeSessionStateStore implements StateStore
{
    private const MAX_PENDING = 5;

    public function __construct(
        private string $sessionKey = '_bannerstop_keycloak_logins',
    ) {
    }

    public function save(PendingLogin $login): void
    {
        $pending = $this->all();
        $pending[$login->getState()] = $login->toArray();
        // Only the most recent logins are kept, so abandoned ones cannot pile up.
        $_SESSION[$this->sessionKey] = array_slice($pending, -self::MAX_PENDING, null, true);
    }

    public function take(string $state): ?PendingLogin
    {
        $pending = $this->all();
        $data = $pending[$state] ?? null;
        unset($pending[$state]);
        $_SESSION[$this->sessionKey] = $pending;

        return is_array($data) ? PendingLogin::fromArray($data) : null;
    }

    /**
     * @return array<string, mixed>
     */
    private function all(): array
    {
        if (PHP_SESSION_ACTIVE !== session_status()) {
            throw new \LogicException('Start the session before using NativeSessionStateStore.');
        }
        $pending = $_SESSION[$this->sessionKey] ?? [];

        return is_array($pending) ? $pending : [];
    }
}
