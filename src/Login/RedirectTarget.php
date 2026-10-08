<?php

declare(strict_types=1);

namespace Bannerstop\Keycloak\Login;

/**
 * Guards the "return to" URL of a login against open redirects.
 */
final class RedirectTarget
{
    private function __construct()
    {
    }

    /**
     * True for a path on the current host, such as "/orders?page=2". Rejects
     * absolute and protocol-relative URLs ("//evil.example"), backslash
     * tricks and control characters.
     */
    public static function isLocal(?string $target): bool
    {
        if (null === $target || '' === $target || '/' !== $target[0]) {
            return false;
        }
        if (1 === preg_match('/[\x00-\x1f\x7f\\\\]/', $target)) {
            return false;
        }
        $parts = parse_url($target);

        return false !== $parts && !isset($parts['scheme']) && !isset($parts['host']) && 0 !== strpos($target, '//');
    }
}
