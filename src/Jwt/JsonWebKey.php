<?php

declare(strict_types=1);

namespace Bannerstop\Keycloak\Jwt;

use Bannerstop\Keycloak\Support\Base64Url;

/**
 * A public signing key from the realm's JWKS.
 */
final readonly class JsonWebKey
{
    private const MIN_RSA_BITS = 2048;
    private const CURVE_SIZES = ['P-256' => 32, 'P-384' => 48, 'P-521' => 66, 'Ed25519' => 32];

    private function __construct(
        private ?string $keyId,
        private string $keyType,
        private ?Algorithm $algorithm,
        private ?string $curve,
        /** @var string PEM for RSA and EC, the raw 32 byte public key for Ed25519 */
        private string $material
    )
    {
    }

    /**
     * @param array<mixed> $jwk
     *
     * @return self|null Null for keys that cannot verify signatures: encryption
     *                   keys, unknown key types or keys that are too weak
     */
    public static function fromArray(array $jwk): ?self
    {
        $keyType = self::stringParameter($jwk, 'kty');
        $use = self::stringParameter($jwk, 'use');
        if (null === $keyType || (null !== $use && 'sig' !== $use)) {
            return null;
        }
        $keyId = self::stringParameter($jwk, 'kid');
        $name = self::stringParameter($jwk, 'alg');
        $algorithm = null === $name ? null : Algorithm::tryFrom($name);
        if (null !== $name && (null === $algorithm || $algorithm->keyType() !== $keyType)) {
            return null;
        }

        return match ($keyType) {
            'RSA' => self::rsa($jwk, $keyId, $algorithm),
            'EC' => self::ec($jwk, $keyId, $algorithm),
            'OKP' => self::okp($jwk, $keyId, $algorithm),
            default => null,
        };
    }

    /**
     * @param array<mixed> $jwk
     */
    private static function rsa(array $jwk, ?string $keyId, ?Algorithm $algorithm): ?self
    {
        $modulus = self::binaryParameter($jwk, 'n');
        $exponent = self::binaryParameter($jwk, 'e');
        if (null === $modulus || null === $exponent || 8 * strlen(ltrim($modulus, "\x00")) < self::MIN_RSA_BITS) {
            return null;
        }

        return new self($keyId, 'RSA', $algorithm, null, Der::rsaPublicKeyPem($modulus, $exponent));
    }

    /**
     * @param array<mixed> $jwk
     */
    private static function ec(array $jwk, ?string $keyId, ?Algorithm $algorithm): ?self
    {
        $curve = self::stringParameter($jwk, 'crv');
        $x = self::binaryParameter($jwk, 'x');
        $y = self::binaryParameter($jwk, 'y');
        $size = self::CURVE_SIZES[$curve ?? ''] ?? null;
        if ('Ed25519' === $curve || null === $size || null === $x || null === $y || strlen($x) !== $size || strlen($y) !== $size) {
            return null;
        }

        return new self($keyId, 'EC', $algorithm, $curve, Der::ecPublicKeyPem((string) $curve, $x, $y));
    }

    /**
     * @param array<mixed> $jwk
     */
    private static function okp(array $jwk, ?string $keyId, ?Algorithm $algorithm): ?self
    {
        $x = self::binaryParameter($jwk, 'x');
        if ('Ed25519' !== self::stringParameter($jwk, 'crv') || null === $x || strlen($x) !== self::CURVE_SIZES['Ed25519']) {
            return null;
        }

        return new self($keyId, 'OKP', $algorithm, 'Ed25519', $x);
    }

    public function getKeyId(): ?string
    {
        return $this->keyId;
    }

    public function getKeyType(): string
    {
        return $this->keyType;
    }

    public function getAlgorithm(): ?Algorithm
    {
        return $this->algorithm;
    }

    /**
     * Whether this key may verify a signature made with the given algorithm.
     */
    public function supports(Algorithm $algorithm): bool
    {
        if ($algorithm->keyType() !== $this->keyType) {
            return false;
        }
        if (null !== $this->algorithm && $this->algorithm !== $algorithm) {
            return false;
        }

        return null === $algorithm->curve() || $algorithm->curve() === $this->curve;
    }

    public function verify(Algorithm $algorithm, string $signingInput, string $signature): bool
    {
        if (!$this->supports($algorithm)) {
            return false;
        }
        if ('OKP' === $this->keyType) {
            if (!function_exists('sodium_crypto_sign_verify_detached') || SODIUM_CRYPTO_SIGN_BYTES !== strlen($signature)) {
                return false;
            }

            return sodium_crypto_sign_verify_detached($signature, $signingInput, $this->material);
        }
        if ('EC' === $this->keyType) {
            $signature = Der::ecdsaSignature($signature, self::CURVE_SIZES[(string) $this->curve]);
            if (null === $signature) {
                return false;
            }
        }

        return 1 === openssl_verify($signingInput, $signature, $this->material, $algorithm->opensslHash());
    }

    /**
     * @param array<mixed> $jwk
     */
    private static function stringParameter(array $jwk, string $name): ?string
    {
        return isset($jwk[$name]) && is_string($jwk[$name]) && '' !== $jwk[$name] ? $jwk[$name] : null;
    }

    /**
     * @param array<mixed> $jwk
     */
    private static function binaryParameter(array $jwk, string $name): ?string
    {
        $value = self::stringParameter($jwk, $name);
        $decoded = null === $value ? null : Base64Url::decode($value);

        return null === $decoded || '' === $decoded ? null : $decoded;
    }
}
