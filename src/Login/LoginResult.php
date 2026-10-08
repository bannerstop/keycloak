<?php

declare(strict_types=1);

namespace Bannerstop\Keycloak\Login;

use Bannerstop\Keycloak\Identity;
use Bannerstop\Keycloak\Token\TokenSet;

final class LoginResult
{
    private Identity $identity;
    private TokenSet $tokens;
    private ?string $returnTo;

    public function __construct(Identity $identity, TokenSet $tokens, ?string $returnTo)
    {
        $this->identity = $identity;
        $this->tokens = $tokens;
        $this->returnTo = $returnTo;
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
