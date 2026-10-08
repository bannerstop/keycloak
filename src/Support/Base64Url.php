<?php

declare(strict_types=1);

namespace Bannerstop\Keycloak\Support;

/**
 * @internal
 */
final class Base64Url
{
    public static function encode(string $data): string
    {
        return rtrim(strtr(base64_encode($data), '+/', '-_'), '=');
    }

    /**
     * @return string|null Null if the input is not valid base64url
     */
    public static function decode(string $data): ?string
    {
        if (1 !== preg_match('/^[A-Za-z0-9_-]*$/', $data)) {
            return null;
        }
        $decoded = base64_decode(strtr($data, '-_', '+/'), true);

        return false === $decoded ? null : $decoded;
    }
}
