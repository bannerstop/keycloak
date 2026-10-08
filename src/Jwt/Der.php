<?php

declare(strict_types=1);

namespace Bannerstop\Keycloak\Jwt;

/**
 * Just enough DER to turn JWK parameters into keys OpenSSL accepts and raw
 * ECDSA signatures into the ASN.1 form it verifies.
 *
 * @internal
 */
final class Der
{
    private const OID_RSA_ENCRYPTION = "\x06\x09\x2a\x86\x48\x86\xf7\x0d\x01\x01\x01";
    private const OID_EC_PUBLIC_KEY = "\x06\x07\x2a\x86\x48\xce\x3d\x02\x01";
    private const OID_CURVES = [
        'P-256' => "\x06\x08\x2a\x86\x48\xce\x3d\x03\x01\x07",
        'P-384' => "\x06\x05\x2b\x81\x04\x00\x22",
        'P-521' => "\x06\x05\x2b\x81\x04\x00\x23",
    ];
    private const ASN1_NULL = "\x05\x00";

    private function __construct()
    {
    }

    public static function rsaPublicKeyPem(string $modulus, string $exponent): string
    {
        $rsaKey = self::sequence(self::unsignedInteger($modulus) . self::unsignedInteger($exponent));
        $algorithm = self::sequence(self::OID_RSA_ENCRYPTION . self::ASN1_NULL);

        return self::pem(self::sequence($algorithm . self::bitString($rsaKey)));
    }

    public static function ecPublicKeyPem(string $curve, string $x, string $y): string
    {
        if (!isset(self::OID_CURVES[$curve])) {
            throw new \InvalidArgumentException(sprintf('Unsupported curve "%s".', $curve));
        }
        $algorithm = self::sequence(self::OID_EC_PUBLIC_KEY . self::OID_CURVES[$curve]);

        return self::pem(self::sequence($algorithm . self::bitString("\x04" . $x . $y)));
    }

    /**
     * JWS carries ECDSA signatures as r || s (RFC 7518 3.4), OpenSSL wants
     * SEQUENCE { INTEGER r, INTEGER s }.
     */
    public static function ecdsaSignature(string $raw, int $partLength): ?string
    {
        if (strlen($raw) !== 2 * $partLength) {
            return null;
        }

        return self::sequence(self::unsignedInteger(substr($raw, 0, $partLength)) . self::unsignedInteger(substr($raw, $partLength)));
    }

    private static function unsignedInteger(string $bytes): string
    {
        $bytes = ltrim($bytes, "\x00");
        if ('' === $bytes || ord($bytes[0]) > 0x7f) {
            $bytes = "\x00" . $bytes;
        }

        return "\x02" . self::length(strlen($bytes)) . $bytes;
    }

    private static function sequence(string $content): string
    {
        return "\x30" . self::length(strlen($content)) . $content;
    }

    private static function bitString(string $content): string
    {
        return "\x03" . self::length(strlen($content) + 1) . "\x00" . $content;
    }

    private static function length(int $length): string
    {
        if ($length < 0x80) {
            return chr($length);
        }
        $bytes = ltrim(pack('N', $length), "\x00");

        return chr(0x80 | strlen($bytes)) . $bytes;
    }

    private static function pem(string $der): string
    {
        return "-----BEGIN PUBLIC KEY-----\n" . chunk_split(base64_encode($der), 64, "\n") . "-----END PUBLIC KEY-----\n";
    }
}
