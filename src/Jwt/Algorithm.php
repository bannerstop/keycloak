<?php

declare(strict_types=1);

namespace Bannerstop\Keycloak\Jwt;

/**
 * The asymmetric JWS algorithms this library can verify.
 *
 * Symmetric algorithms (HS256 and friends) and "none" are deliberately not
 * supported: with a public key set they only open the door to key confusion.
 */
final class Algorithm
{
    public const RS256 = 'RS256';
    public const RS384 = 'RS384';
    public const RS512 = 'RS512';
    public const ES256 = 'ES256';
    public const ES384 = 'ES384';
    public const ES512 = 'ES512';
    public const EDDSA = 'EdDSA';

    private const DEFINITIONS = [
        self::RS256 => ['kty' => 'RSA', 'hash' => OPENSSL_ALGO_SHA256, 'crv' => null],
        self::RS384 => ['kty' => 'RSA', 'hash' => OPENSSL_ALGO_SHA384, 'crv' => null],
        self::RS512 => ['kty' => 'RSA', 'hash' => OPENSSL_ALGO_SHA512, 'crv' => null],
        self::ES256 => ['kty' => 'EC', 'hash' => OPENSSL_ALGO_SHA256, 'crv' => 'P-256'],
        self::ES384 => ['kty' => 'EC', 'hash' => OPENSSL_ALGO_SHA384, 'crv' => 'P-384'],
        self::ES512 => ['kty' => 'EC', 'hash' => OPENSSL_ALGO_SHA512, 'crv' => 'P-521'],
        self::EDDSA => ['kty' => 'OKP', 'hash' => null, 'crv' => 'Ed25519'],
    ];

    private function __construct()
    {
    }

    public static function isSupported(string $algorithm): bool
    {
        return isset(self::DEFINITIONS[$algorithm]);
    }

    /**
     * @return string[]
     */
    public static function all(): array
    {
        return array_keys(self::DEFINITIONS);
    }

    public static function keyType(string $algorithm): string
    {
        return self::definition($algorithm)['kty'];
    }

    public static function opensslHash(string $algorithm): int
    {
        $hash = self::definition($algorithm)['hash'];
        if (null === $hash) {
            throw new \LogicException(sprintf('%s is not verified through OpenSSL.', $algorithm));
        }

        return $hash;
    }

    /**
     * The curve an EC or OKP key must use for this algorithm, null for RSA.
     */
    public static function curve(string $algorithm): ?string
    {
        return self::definition($algorithm)['crv'];
    }

    /**
     * @return array{kty: string, hash: int|null, crv: string|null}
     */
    private static function definition(string $algorithm): array
    {
        if (!isset(self::DEFINITIONS[$algorithm])) {
            throw new \InvalidArgumentException(sprintf('Unsupported algorithm "%s".', $algorithm));
        }

        return self::DEFINITIONS[$algorithm];
    }
}
