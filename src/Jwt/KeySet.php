<?php

declare(strict_types=1);

namespace Bannerstop\Keycloak\Jwt;

final class KeySet
{
    /** @var JsonWebKey[] */
    private readonly array $keys;

    /**
     * @param JsonWebKey[] $keys
     */
    public function __construct(array $keys)
    {
        $this->keys = array_values($keys);
    }

    /**
     * @param array<mixed> $document A JWKS document ({"keys": [...]})
     */
    public static function fromArray(array $document): self
    {
        $keys = [];
        foreach (isset($document['keys']) && is_array($document['keys']) ? $document['keys'] : [] as $jwk) {
            $key = is_array($jwk) ? JsonWebKey::fromArray($jwk) : null;
            if (null !== $key) {
                $keys[] = $key;
            }
        }

        return new self($keys);
    }

    /**
     * Finds the key for a token header. Without a kid the token is only
     * accepted when exactly one key fits the algorithm.
     */
    public function find(?string $keyId, Algorithm $algorithm): ?JsonWebKey
    {
        $candidates = [];
        foreach ($this->keys as $key) {
            if (!$key->supports($algorithm)) {
                continue;
            }
            if (null !== $keyId && $key->getKeyId() === $keyId) {
                return $key;
            }
            $candidates[] = $key;
        }

        return null === $keyId && 1 === count($candidates) ? $candidates[0] : null;
    }

    public function isEmpty(): bool
    {
        return [] === $this->keys;
    }
}
