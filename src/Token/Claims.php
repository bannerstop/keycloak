<?php

declare(strict_types=1);

namespace Bannerstop\Keycloak\Token;

/**
 * Verified token claims with typed accessors, so callers never have to cast
 * values out of a raw array.
 */
final class Claims
{
    /**
     * @param array<string, mixed> $claims
     */
    public function __construct(
        private array $claims,
    ) {
    }

    public function has(string $name): bool
    {
        return array_key_exists($name, $this->claims);
    }

    public function get(string $name): mixed
    {
        return $this->claims[$name] ?? null;
    }

    public function getString(string $name): ?string
    {
        $value = $this->get($name);

        return is_string($value) && '' !== $value ? $value : null;
    }

    public function getInt(string $name): ?int
    {
        $value = $this->get($name);
        if (is_int($value)) {
            return $value;
        }

        return is_float($value) && is_finite($value) ? (int) $value : null;
    }

    public function getBool(string $name): bool
    {
        $value = $this->get($name);

        // Some providers send booleans as strings.
        return true === $value || 'true' === $value;
    }

    /**
     * A claim that may be a single string or a list of strings, like "aud".
     *
     * @return string[]
     */
    public function getStringList(string $name): array
    {
        $value = $this->get($name);
        if (is_string($value)) {
            return '' === $value ? [] : [$value];
        }
        if (!is_array($value)) {
            return [];
        }

        return array_values(array_filter($value, static fn ($item): bool => is_string($item) && '' !== $item));
    }

    /**
     * Reads a nested object claim like realm_access.roles.
     *
     * @param string[] $path
     */
    public function getPath(array $path): mixed
    {
        $value = $this->claims;
        foreach ($path as $segment) {
            if (!is_array($value) || !array_key_exists($segment, $value)) {
                return null;
            }
            $value = $value[$segment];
        }

        return $value;
    }

    /**
     * Claims of the other set win where both define a name.
     */
    public function merge(self $other): self
    {
        return new self(array_merge($this->claims, $other->claims));
    }

    /**
     * @return array<string, mixed>
     */
    public function all(): array
    {
        return $this->claims;
    }
}
