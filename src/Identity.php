<?php

declare(strict_types=1);

namespace Bannerstop\Keycloak;

use Bannerstop\Keycloak\Token\Claims;

/**
 * The verified user behind a login or an access token.
 */
final readonly class Identity
{
    private string $subject;

    public function __construct(private Claims $claims)
    {
        $this->subject = $this->claims->getString('sub') ?? throw new \InvalidArgumentException('An identity needs a subject.');
    }

    /**
     * The stable, unique user id in the realm. Use it to link accounts, not
     * the e-mail address or the username, which can both change.
     */
    public function getSubject(): string
    {
        return $this->subject;
    }

    /**
     * Lower-cased e-mail address, null if the token carries none.
     */
    public function getEmail(): ?string
    {
        $email = $this->claims->getString('email');

        return null === $email ? null : strtolower(trim($email));
    }

    public function isEmailVerified(): bool
    {
        return $this->claims->getBool('email_verified');
    }

    public function getEmailDomain(): ?string
    {
        $email = $this->getEmail();
        $at = null === $email ? false : strrpos($email, '@');

        return false === $at ? null : (string) substr((string) $email, $at + 1);
    }

    /**
     * Keycloak's session id ("sid"), which back-channel logout tokens name.
     */
    public function getSessionId(): ?string
    {
        return $this->claims->getString('sid');
    }

    public function getUsername(): ?string
    {
        return $this->claims->getString('preferred_username');
    }

    public function getGivenName(): ?string
    {
        return $this->claims->getString('given_name');
    }

    public function getFamilyName(): ?string
    {
        return $this->claims->getString('family_name');
    }

    /**
     * The best display name available: name, then given and family name,
     * then username, then e-mail address.
     */
    public function getDisplayName(): string
    {
        $name = $this->claims->getString('name');
        if (null !== $name) {
            return $name;
        }
        $parts = array_filter([$this->getGivenName(), $this->getFamilyName()], static fn (?string $part): bool => null !== $part);
        if ([] !== $parts) {
            return implode(' ', $parts);
        }

        return $this->getUsername() ?? $this->getEmail() ?? $this->subject;
    }

    /**
     * @return string[]
     */
    public function getRealmRoles(): array
    {
        return self::stringList($this->claims->getPath(['realm_access', 'roles']));
    }

    /**
     * @return string[]
     */
    public function getClientRoles(string $clientId): array
    {
        return self::stringList($this->claims->getPath(['resource_access', $clientId, 'roles']));
    }

    /**
     * Group names as the group membership mapper writes them: plain names, or
     * paths like "/staff/it" when "Full group path" is on.
     *
     * @return string[]
     */
    public function getGroups(): array
    {
        return $this->claims->getStringList('groups');
    }

    public function getClaims(): Claims
    {
        return $this->claims;
    }

    /**
     * @return string[]
     */
    private static function stringList(mixed $value): array
    {
        return new Claims(['list' => $value])->getStringList('list');
    }
}
