<?php

declare(strict_types=1);

namespace Bannerstop\Keycloak\Jwt;

use Bannerstop\Keycloak\Exception\InvalidTokenException;
use Bannerstop\Keycloak\Support\Base64Url;

/**
 * A decoded, not yet verified JWS in compact serialization.
 *
 * @internal
 */
final class Jwt
{
    private const int MAX_LENGTH = 65536;

    /**
     * @param array<mixed> $header
     * @param array<mixed> $payload
     */
    private function __construct(
        private array $header,
        private readonly array $payload,
        private readonly string $signingInput,
        private readonly string $signature,
    ) {
    }

    public static function parse(#[\SensitiveParameter] string $token): self
    {
        if (strlen($token) > self::MAX_LENGTH) {
            throw new InvalidTokenException('The token is too long.');
        }
        $parts = explode('.', $token);
        if (3 !== count($parts)) {
            throw new InvalidTokenException('The token is not a signed JWT.');
        }
        $header = self::decodeJson($parts[0]);
        $payload = self::decodeJson($parts[1]);
        $signature = Base64Url::decode($parts[2]);
        if (null === $header || null === $payload || null === $signature || '' === $signature) {
            throw new InvalidTokenException('The token is malformed.');
        }

        return new self($header, $payload, $parts[0] . '.' . $parts[1], $signature);
    }

    public function getAlgorithm(): ?string
    {
        return isset($this->header['alg']) && is_string($this->header['alg']) ? $this->header['alg'] : null;
    }

    public function getKeyId(): ?string
    {
        return isset($this->header['kid']) && is_string($this->header['kid']) ? $this->header['kid'] : null;
    }

    /**
     * Header parameters this library does not understand must make the token
     * invalid if they are marked critical (RFC 7515 4.1.11).
     */
    public function hasCriticalHeader(): bool
    {
        return array_key_exists('crit', $this->header);
    }

    /**
     * @return array<mixed>
     */
    public function getPayload(): array
    {
        return $this->payload;
    }

    public function getSigningInput(): string
    {
        return $this->signingInput;
    }

    public function getSignature(): string
    {
        return $this->signature;
    }

    /**
     * @return array<mixed>|null
     */
    private static function decodeJson(string $segment): ?array
    {
        $json = Base64Url::decode($segment);
        if (null === $json) {
            return null;
        }
        try {
            $data = json_decode($json, true, 32, JSON_THROW_ON_ERROR);
        } catch (\JsonException) {
            return null;
        }

        // A JWT header or payload is a JSON object, never a list.
        return is_array($data) && ([] === $data || !array_is_list($data)) ? $data : null;
    }
}
