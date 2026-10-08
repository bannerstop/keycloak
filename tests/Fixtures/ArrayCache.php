<?php

declare(strict_types=1);

namespace Bannerstop\Keycloak\Tests\Fixtures;

use Psr\SimpleCache\CacheInterface;

final class ArrayCache implements CacheInterface
{
    /** @var array<string, mixed> */
    public array $values = [];

    #[\Override]
    public function get(string $key, mixed $default = null): mixed
    {
        return $this->values[$key] ?? $default;
    }

    #[\Override]
    public function set(string $key, mixed $value, null|int|\DateInterval $ttl = null): bool
    {
        $this->values[$key] = $value;

        return true;
    }

    #[\Override]
    public function delete(string $key): bool
    {
        unset($this->values[$key]);

        return true;
    }

    #[\Override]
    public function clear(): bool
    {
        $this->values = [];

        return true;
    }

    /**
     * @param iterable<string> $keys
     *
     * @return iterable<string, mixed>
     */
    #[\Override]
    public function getMultiple(iterable $keys, mixed $default = null): iterable
    {
        $values = [];
        foreach ($keys as $key) {
            $values[$key] = $this->get($key, $default);
        }

        return $values;
    }

    /**
     * @param iterable<string, mixed> $values
     */
    #[\Override]
    public function setMultiple(iterable $values, null|int|\DateInterval $ttl = null): bool
    {
        foreach ($values as $key => $value) {
            $this->set($key, $value);
        }

        return true;
    }

    /**
     * @param iterable<string> $keys
     */
    #[\Override]
    public function deleteMultiple(iterable $keys): bool
    {
        foreach ($keys as $key) {
            $this->delete($key);
        }

        return true;
    }

    #[\Override]
    public function has(string $key): bool
    {
        return array_key_exists($key, $this->values);
    }
}
