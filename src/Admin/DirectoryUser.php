<?php

declare(strict_types=1);

namespace Bannerstop\Keycloak\Admin;

/**
 * A user as the admin API lists it.
 */
final class DirectoryUser
{
    /** @var string */
    private $id;

    /** @var string */
    private $username;

    /** @var string|null */
    private $email;

    /** @var string|null */
    private $firstName;

    /** @var string|null */
    private $lastName;

    /** @var bool */
    private $enabled;

    /** @var bool */
    private $emailVerified;

    public function __construct(string $id, string $username, ?string $email, ?string $firstName, ?string $lastName, bool $enabled, bool $emailVerified)
    {
        $this->id = $id;
        $this->username = $username;
        $this->email = $email;
        $this->firstName = $firstName;
        $this->lastName = $lastName;
        $this->enabled = $enabled;
        $this->emailVerified = $emailVerified;
    }

    /**
     * @param array<mixed> $representation A UserRepresentation of the admin API
     */
    public static function fromArray(array $representation): ?self
    {
        $string = static function (string $field) use ($representation): ?string {
            return isset($representation[$field]) && is_string($representation[$field]) && '' !== trim($representation[$field]) ? trim($representation[$field]) : null;
        };
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
        $parts = array_filter([$this->firstName, $this->lastName], static function (?string $part): bool {
            return null !== $part;
        });

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
