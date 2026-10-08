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
    /** @var CacheInterface|null */
    private $cache;

    /** @var array<string, mixed> */
    private $memory = [];

    public function __construct(?CacheInterface $cache = null)
    {
        $this->cache = $cache;
    }

    /**
     * @return mixed|null
     */
    public function get(string $key)
    {
        if (array_key_exists($key, $this->memory)) {
            return $this->memory[$key];
        }
        if (null === $this->cache) {
            return null;
        }
        try {
            $value = $this->cache->get($key);
        } catch (InvalidArgumentException $exception) {
            return null;
        }
        if (null !== $value) {
            $this->memory[$key] = $value;
        }

        return $value;
    }

    /**
     * @param mixed $value
     */
    public function set(string $key, $value, int $ttl): void
    {
        $this->memory[$key] = $value;
        if (null === $this->cache) {
            return;
        }
        try {
            $this->cache->set($key, $value, $ttl);
        } catch (InvalidArgumentException $exception) {
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
        } catch (InvalidArgumentException $exception) {
        }
    }
}
