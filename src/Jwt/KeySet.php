<?php

declare(strict_types=1);

namespace Bannerstop\Keycloak\Jwt;

final readonly class KeySet
{
    /** @var JsonWebKey[] */
    private array $keys;

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
        $candidates = array_values(array_filter($this->keys, static fn (JsonWebKey $key): bool => $key->supports($algorithm)));
        if (null !== $keyId) {
            return array_find($candidates, static fn (JsonWebKey $key): bool => $key->getKeyId() === $keyId);
        }

        return 1 === count($candidates) ? $candidates[0] : null;
    }

    public function isEmpty(): bool
    {
        return [] === $this->keys;
    }
}
