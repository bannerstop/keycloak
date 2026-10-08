<?php

declare(strict_types=1);

namespace Bannerstop\Keycloak\Policy;

use Bannerstop\Keycloak\Identity;

/**
 * Decides whether a verified identity may sign in to the application.
 */
interface IdentityPolicy
{
    public function allows(Identity $identity): bool;
}
