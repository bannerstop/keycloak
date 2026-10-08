<?php

declare(strict_types=1);

namespace Bannerstop\Keycloak\Bearer;

final class BearerToken
{
    private function __construct()
    {
    }

    /**
     * Extracts the token from an "Authorization: Bearer <token>" header (RFC 6750 2.1).
     */
    public static function fromAuthorizationHeader(?string $header): ?string
    {
        if (null === $header || 1 !== preg_match('/^Bearer +([A-Za-z0-9\-._~+\/]+=*)$/i', trim($header), $match)) {
            return null;
        }

        return $match[1];
    }
}
