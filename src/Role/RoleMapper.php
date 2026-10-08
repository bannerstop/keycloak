<?php

declare(strict_types=1);

namespace Bannerstop\Keycloak\Role;

use Bannerstop\Keycloak\Exception\ConfigurationException;
use Bannerstop\Keycloak\Identity;

/**
 * Turns Keycloak realm roles, client roles and groups into the role names of
 * an application, e.g. the realm role "admin" into "ROLE_ADMIN".
 *
 * Only explicitly mapped roles and groups count. Nothing from the token is
 * passed through as is, so a new role in Keycloak never grants access by
 * accident.
 */
final readonly class RoleMapper
{
    /**
     * @param string[]                               $defaultRoles Roles every authenticated user gets
     * @param array<string, string[]>                $realmRoles
     * @param array<string, array<string, string[]>> $clientRoles
     * @param array<string, string[]>                $groups
     */
    public function __construct(
        private array $defaultRoles = [],
        private array $realmRoles = [],
        private array $clientRoles = [],
        private array $groups = [],
    ) {
    }

    /**
     * @param array{default_roles?: string[], realm_roles?: array<string, string[]>, client_roles?: array<string, array<string, string[]>>, groups?: array<string, string[]>} $config
     */
    public static function fromArray(array $config): self
    {
        $mapper = new self(self::roleList($config['default_roles'] ?? [], 'default_roles'));
        foreach (self::table($config['realm_roles'] ?? [], 'realm_roles') as $role => $roles) {
            $mapper = $mapper->withRealmRole((string) $role, self::roleList($roles, 'realm_roles'));
        }
        foreach (self::table($config['client_roles'] ?? [], 'client_roles') as $clientId => $mapping) {
            foreach (self::table($mapping, 'client_roles') as $role => $roles) {
                $mapper = $mapper->withClientRole((string) $clientId, (string) $role, self::roleList($roles, 'client_roles'));
            }
        }
        foreach (self::table($config['groups'] ?? [], 'groups') as $group => $roles) {
            $mapper = $mapper->withGroup((string) $group, self::roleList($roles, 'groups'));
        }

        return $mapper;
    }

    /**
     * @param string[] $roles
     */
    #[\NoDiscard]
    public function withRealmRole(string $keycloakRole, array $roles): self
    {
        $realmRoles = $this->realmRoles;
        $realmRoles[$keycloakRole] = [...$realmRoles[$keycloakRole] ?? [], ...$roles];

        return clone($this, ['realmRoles' => $realmRoles]);
    }

    /**
     * @param string[] $roles
     */
    #[\NoDiscard]
    public function withClientRole(string $clientId, string $keycloakRole, array $roles): self
    {
        $clientRoles = $this->clientRoles;
        $clientRoles[$clientId][$keycloakRole] = [...$clientRoles[$clientId][$keycloakRole] ?? [], ...$roles];

        return clone($this, ['clientRoles' => $clientRoles]);
    }

    /**
     * @param string   $group The group as it appears in the token: a name, or a path like "/staff/it"
     * @param string[] $roles
     */
    #[\NoDiscard]
    public function withGroup(string $group, array $roles): self
    {
        $groups = $this->groups;
        $groups[$group] = [...$groups[$group] ?? [], ...$roles];

        return clone($this, ['groups' => $groups]);
    }

    /**
     * @return string[]
     */
    public function map(Identity $identity): array
    {
        $roles = $this->defaultRoles;
        foreach ($identity->getRealmRoles() as $role) {
            $roles = array_merge($roles, $this->realmRoles[$role] ?? []);
        }
        foreach ($this->clientRoles as $clientId => $mapping) {
            foreach ($identity->getClientRoles($clientId) as $role) {
                $roles = array_merge($roles, $mapping[$role] ?? []);
            }
        }
        foreach ($identity->getGroups() as $group) {
            $roles = array_merge($roles, $this->groups[$group] ?? []);
        }

        return array_values(array_unique($roles));
    }

    /**
     * @return array<mixed>
     */
    private static function table(mixed $value, string $option): array
    {
        if (!is_array($value)) {
            throw new ConfigurationException(sprintf('The role mapping "%s" must be a map.', $option));
        }

        return $value;
    }

    /**
     * @return string[]
     */
    private static function roleList(mixed $value, string $option): array
    {
        $roles = is_string($value) ? [$value] : $value;
        if (!is_array($roles)) {
            throw new ConfigurationException(sprintf('The role mapping "%s" must map to a role or a list of roles.', $option));
        }
        foreach ($roles as $role) {
            if (!is_string($role) || '' === $role) {
                throw new ConfigurationException(sprintf('The role mapping "%s" contains an invalid role name.', $option));
            }
        }

        return array_values($roles);
    }
}
