<?php

declare(strict_types=1);

namespace Bannerstop\Keycloak\Jwt;

/**
 * The asymmetric JWS algorithms this library can verify.
 *
 * Symmetric algorithms (HS256 and friends) and "none" are deliberately not
 * supported: with a public key set they only open the door to key confusion.
 */
enum Algorithm: string
{
    case RS256 = 'RS256';
    case RS384 = 'RS384';
    case RS512 = 'RS512';
    case ES256 = 'ES256';
    case ES384 = 'ES384';
    case ES512 = 'ES512';
    case EdDSA = 'EdDSA';

    /**
     * The JWK key type ("kty") a key needs for this algorithm.
     */
    public function keyType(): string
    {
        return match ($this) {
            self::RS256, self::RS384, self::RS512 => 'RSA',
            self::ES256, self::ES384, self::ES512 => 'EC',
            self::EdDSA => 'OKP',
        };
    }

    /**
     * The curve an EC or OKP key must use, null for RSA.
     */
    public function curve(): ?string
    {
        return match ($this) {
            self::ES256 => 'P-256',
            self::ES384 => 'P-384',
            self::ES512 => 'P-521',
            self::EdDSA => 'Ed25519',
            default => null,
        };
    }

    public function opensslHash(): int
    {
        return match ($this) {
            self::RS256, self::ES256 => OPENSSL_ALGO_SHA256,
            self::RS384, self::ES384 => OPENSSL_ALGO_SHA384,
            self::RS512, self::ES512 => OPENSSL_ALGO_SHA512,
            self::EdDSA => throw new \LogicException('EdDSA is not verified through OpenSSL.'),
        };
    }

    /**
     * @return string[]
     */
    public static function names(): array
    {
        return array_column(self::cases(), 'value');
    }
}
