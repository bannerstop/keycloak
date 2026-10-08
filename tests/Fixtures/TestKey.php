<?php

declare(strict_types=1);

namespace Bannerstop\Keycloak\Tests\Fixtures;

use Bannerstop\Keycloak\Support\Base64Url;

/**
 * A generated key pair that signs test tokens and publishes itself as JWK.
 */
final class TestKey
{
    private const EC_SIZES = ['prime256v1' => 32, 'secp384r1' => 48, 'secp521r1' => 66];

    /** @var resource|\OpenSSLAsymmetricKey */
    private $privateKey;

    /** @var array<string, string> */
    private $jwk;

    /** @var string */
    public $algorithm;

    /** @var string */
    public $kid;

    /** @var int|null */
    private $ecSize;

    /**
     * @param resource|\OpenSSLAsymmetricKey $privateKey
     * @param array<string, string>          $jwk
     */
    private function __construct($privateKey, array $jwk, string $algorithm, string $kid, ?int $ecSize = null)
    {
        $this->ecSize = $ecSize;
        $this->privateKey = $privateKey;
        $this->jwk = $jwk;
        $this->algorithm = $algorithm;
        $this->kid = $kid;
    }

    public static function rsa(string $kid = 'rsa-key', int $bits = 2048, string $algorithm = 'RS256'): self
    {
        $key = openssl_pkey_new(['private_key_type' => OPENSSL_KEYTYPE_RSA, 'private_key_bits' => $bits]);
        $details = openssl_pkey_get_details($key);

        return new self($key, [
            'kid' => $kid,
            'kty' => 'RSA',
            'alg' => $algorithm,
            'use' => 'sig',
            'n' => Base64Url::encode($details['rsa']['n']),
            'e' => Base64Url::encode($details['rsa']['e']),
        ], $algorithm, $kid);
    }

    public static function ec(string $curveName = 'prime256v1', string $algorithm = 'ES256', string $kid = 'ec-key'): self
    {
        $key = openssl_pkey_new(['private_key_type' => OPENSSL_KEYTYPE_EC, 'curve_name' => $curveName]);
        $details = openssl_pkey_get_details($key);
        $size = self::EC_SIZES[$curveName];
        $crv = ['prime256v1' => 'P-256', 'secp384r1' => 'P-384', 'secp521r1' => 'P-521'][$curveName];

        return new self($key, [
            'kid' => $kid,
            'kty' => 'EC',
            'alg' => $algorithm,
            'use' => 'sig',
            'crv' => $crv,
            'x' => Base64Url::encode(str_pad($details['ec']['x'], $size, "\x00", STR_PAD_LEFT)),
            'y' => Base64Url::encode(str_pad($details['ec']['y'], $size, "\x00", STR_PAD_LEFT)),
        ], $algorithm, $kid, $size);
    }

    /**
     * @return array<string, string>
     */
    public function jwk(): array
    {
        return $this->jwk;
    }

    /**
     * @param array<string, mixed> $claims
     * @param array<string, mixed> $header
     */
    public function sign(array $claims, array $header = []): string
    {
        $header = array_merge(['alg' => $this->algorithm, 'typ' => 'JWT', 'kid' => $this->kid], $header);
        $input = Base64Url::encode(json_encode($header)) . '.' . Base64Url::encode(json_encode($claims));
        $hash = ['256' => OPENSSL_ALGO_SHA256, '384' => OPENSSL_ALGO_SHA384, '512' => OPENSSL_ALGO_SHA512][substr($this->algorithm, 2)];
        openssl_sign($input, $signature, $this->privateKey, $hash);
        if (null !== $this->ecSize) {
            $signature = self::derToRaw($signature, $this->ecSize);
        }

        return $input . '.' . Base64Url::encode($signature);
    }

    private static function derToRaw(string $der, int $size): string
    {
        $offset = 2;
        if (0x81 === ord($der[1])) {
            $offset = 3;
        }
        $parts = [];
        for ($i = 0; $i < 2; ++$i) {
            $length = ord($der[$offset + 1]);
            $parts[] = str_pad(ltrim(substr($der, $offset + 2, $length), "\x00"), $size, "\x00", STR_PAD_LEFT);
            $offset += 2 + $length;
        }

        return $parts[0] . $parts[1];
    }
}
