<?php

declare(strict_types=1);

namespace Bannerstop\Keycloak\Jwt;

use Bannerstop\Keycloak\Support\Base64Url;

/**
 * A public signing key from the realm's JWKS.
 */
final class JsonWebKey
{
    private const MIN_RSA_BITS = 2048;
    private const CURVE_SIZES = ['P-256' => 32, 'P-384' => 48, 'P-521' => 66, 'Ed25519' => 32];

    /** @var string|null */
    private $keyId;

    /** @var string */
    private $keyType;

    /** @var string|null */
    private $algorithm;

    /** @var string|null */
    private $curve;

    /** @var string PEM for RSA and EC, the raw 32 byte public key for Ed25519 */
    private $material;

    private function __construct(?string $keyId, string $keyType, ?string $algorithm, ?string $curve, string $material)
    {
        $this->keyId = $keyId;
        $this->keyType = $keyType;
        $this->algorithm = $algorithm;
        $this->curve = $curve;
        $this->material = $material;
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
        $algorithm = self::stringParameter($jwk, 'alg');
        if (null !== $algorithm && (!Algorithm::isSupported($algorithm) || Algorithm::keyType($algorithm) !== $keyType)) {
            return null;
        }

        switch ($keyType) {
            case 'RSA':
                $modulus = self::binaryParameter($jwk, 'n');
                $exponent = self::binaryParameter($jwk, 'e');
                if (null === $modulus || null === $exponent || 8 * strlen(ltrim($modulus, "\x00")) < self::MIN_RSA_BITS) {
                    return null;
                }

                return new self($keyId, $keyType, $algorithm, null, Der::rsaPublicKeyPem($modulus, $exponent));

            case 'EC':
                $curve = self::stringParameter($jwk, 'crv');
                $x = self::binaryParameter($jwk, 'x');
                $y = self::binaryParameter($jwk, 'y');
                if (null === $curve || 'Ed25519' === $curve || !isset(self::CURVE_SIZES[$curve]) || null === $x || null === $y
                    || strlen($x) !== self::CURVE_SIZES[$curve] || strlen($y) !== self::CURVE_SIZES[$curve]) {
                    return null;
                }

                return new self($keyId, $keyType, $algorithm, $curve, Der::ecPublicKeyPem($curve, $x, $y));

            case 'OKP':
                $curve = self::stringParameter($jwk, 'crv');
                $x = self::binaryParameter($jwk, 'x');
                if ('Ed25519' !== $curve || null === $x || strlen($x) !== self::CURVE_SIZES['Ed25519']) {
                    return null;
                }

                return new self($keyId, $keyType, $algorithm, $curve, $x);
        }

        return null;
    }

    public function getKeyId(): ?string
    {
        return $this->keyId;
    }

    public function getKeyType(): string
    {
        return $this->keyType;
    }

    public function getAlgorithm(): ?string
    {
        return $this->algorithm;
    }

    /**
     * Whether this key may verify a signature made with the given algorithm.
     */
    public function supports(string $algorithm): bool
    {
        if (!Algorithm::isSupported($algorithm) || Algorithm::keyType($algorithm) !== $this->keyType) {
            return false;
        }
        if (null !== $this->algorithm && $this->algorithm !== $algorithm) {
            return false;
        }

        return null === Algorithm::curve($algorithm) || Algorithm::curve($algorithm) === $this->curve;
    }

    public function verify(string $algorithm, string $signingInput, string $signature): bool
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

        return 1 === openssl_verify($signingInput, $signature, $this->material, Algorithm::opensslHash($algorithm));
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
