<?php

declare(strict_types=1);

namespace Bannerstop\Keycloak\Login;

use Uri\Rfc3986\Uri;

/**
 * Guards the "return to" URL of a login against open redirects.
 */
final class RedirectTarget
{
    /** Never resolvable (RFC 2606), only used to see where a target leads. */
    private const string PROBE = 'https://local.invalid/';

    private function __construct()
    {
    }

    /**
     * True for a path on the current host, such as "/orders?page=2". The target
     * is resolved like a browser would (RFC 3986); anything that leaves the
     * host ("//evil.example") or is not a valid URI reference (backslashes,
     * control characters) is rejected.
     */
    #[\NoDiscard]
    public static function isLocal(?string $target): bool
    {
        if (null === $target || !str_starts_with($target, '/')) {
            return false;
        }
        $probe = new Uri(self::PROBE);
        $resolved = Uri::parse($target, $probe);

        return null !== $resolved && $resolved->getScheme() === $probe->getScheme() && $resolved->getHost() === $probe->getHost();
    }
}
