<?php

declare(strict_types=1);

namespace Bannerstop\Keycloak\Admin;

/**
 * A user as the admin API lists it.
 */
final class DirectoryUser
{
    public function __construct(
        private readonly string $id,
        private readonly string $username,
        private readonly ?string $email,
        private readonly ?string $firstName,
        private readonly ?string $lastName,
        private readonly bool $enabled,
        private readonly bool $emailVerified,
    ) {
    }

    /**
     * @param array<mixed> $representation A UserRepresentation of the admin API
     */
    public static function fromArray(array $representation): ?self
    {
        $string = static fn (string $field): ?string => isset($representation[$field]) && is_string($representation[$field]) && '' !== trim($representation[$field]) ? trim($representation[$field]) : null;
        $id = $string('id');
        $username = $string('username');
        if (null === $id || null === $username) {
            return null;
        }
        $email = $string('email');

        return new self(
            $id,
            $username,
            null === $email ? null : strtolower($email),
            $string('firstName'),
            $string('lastName'),
            !isset($representation['enabled']) || true === $representation['enabled'],
            isset($representation['emailVerified']) && true === $representation['emailVerified']
        );
    }

    /**
     * The same id as the "sub" claim of the user's tokens.
     */
    public function getId(): string
    {
        return $this->id;
    }

    public function getUsername(): string
    {
        return $this->username;
    }

    public function getEmail(): ?string
    {
        return $this->email;
    }

    public function getFirstName(): ?string
    {
        return $this->firstName;
    }

    public function getLastName(): ?string
    {
        return $this->lastName;
    }

    public function getDisplayName(): string
    {
        $parts = array_filter([$this->firstName, $this->lastName], static fn (?string $part): bool => null !== $part);

        return [] !== $parts ? implode(' ', $parts) : ($this->email ?? $this->username);
    }

    public function isEnabled(): bool
    {
        return $this->enabled;
    }

    public function isEmailVerified(): bool
    {
        return $this->emailVerified;
    }
}
