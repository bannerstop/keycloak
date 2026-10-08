<?php

declare(strict_types=1);

namespace Bannerstop\Keycloak\Login;

use Bannerstop\Keycloak\Identity;
use Bannerstop\Keycloak\Token\TokenSet;

final class LoginResult
{
    public function __construct(
        private readonly Identity $identity,
        private readonly TokenSet $tokens,
        private readonly ?string $returnTo,
    ) {
    }

    public function getIdentity(): Identity
    {
        return $this->identity;
    }

    public function getTokens(): TokenSet
    {
        return $this->tokens;
    }

    /**
     * The value passed to LoginFlow::start(), unvalidated. Check it with
     * RedirectTarget::isLocal() before redirecting to it.
     */
    public function getReturnTo(): ?string
    {
        return $this->returnTo;
    }
}
