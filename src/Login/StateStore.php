<?php

declare(strict_types=1);

namespace Bannerstop\Keycloak\Login;

/**
 * Keeps pending logins between the redirect to Keycloak and the callback,
 * usually in the user's session. Keyed by state, so that logins started in
 * several tabs do not overwrite each other.
 */
interface StateStore
{
    public function save(PendingLogin $login): void;

    /**
     * Returns the pending login for this state and removes it, so that every
     * callback URL works exactly once.
     */
    public function take(string $state): ?PendingLogin;
}
