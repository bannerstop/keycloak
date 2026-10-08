<?php

declare(strict_types=1);

namespace Bannerstop\Keycloak\Support;

use Psr\SimpleCache\CacheInterface;
use Psr\SimpleCache\InvalidArgumentException;

/**
 * Wraps an optional PSR-16 cache. Without one, values live as long as the
 * object, which is one request in a classic PHP setup.
 *
 * A broken cache never breaks a login: errors fall back to the memory copy.
 *
 * @internal
 */
final class Cache
{
    /** @var array<string, mixed> */
    private array $memory = [];

    public function __construct(
        private readonly ?CacheInterface $cache = null,
    ) {
    }

    public function get(string $key): mixed
    {
        if (array_key_exists($key, $this->memory)) {
            return $this->memory[$key];
        }
        if (null === $this->cache) {
            return null;
        }
        try {
            $value = $this->cache->get($key);
        } catch (InvalidArgumentException) {
            return null;
        }
        if (null !== $value) {
            $this->memory[$key] = $value;
        }

        return $value;
    }

    public function set(string $key, mixed $value, int $ttl): void
    {
        $this->memory[$key] = $value;
        if (null === $this->cache) {
            return;
        }
        try {
            $this->cache->set($key, $value, $ttl);
        } catch (InvalidArgumentException) {
        }
    }

    public function delete(string $key): void
    {
        unset($this->memory[$key]);
        if (null === $this->cache) {
            return;
        }
        try {
            $this->cache->delete($key);
        } catch (InvalidArgumentException) {
        }
    }
}
