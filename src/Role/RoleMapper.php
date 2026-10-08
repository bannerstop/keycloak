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
final class RoleMapper
{
    /** @var string[] */
    private array $defaultRoles;

    /** @var array<string, string[]> */
    private array $realmRoles = [];

    /** @var array<string, array<string, string[]>> */
    private array $clientRoles = [];

    /** @var array<string, string[]> */
    private array $groups = [];

    /**
     * @param string[] $defaultRoles Roles every authenticated user gets
     */
    public function __construct(array $defaultRoles = [])
    {
        $this->defaultRoles = array_values($defaultRoles);
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
    public function withRealmRole(string $keycloakRole, array $roles): self
    {
        $mapper = clone $this;
        $mapper->realmRoles[$keycloakRole] = array_merge($this->realmRoles[$keycloakRole] ?? [], $roles);

        return $mapper;
    }

    /**
     * @param string[] $roles
     */
    public function withClientRole(string $clientId, string $keycloakRole, array $roles): self
    {
        $mapper = clone $this;
        $mapper->clientRoles[$clientId][$keycloakRole] = array_merge($this->clientRoles[$clientId][$keycloakRole] ?? [], $roles);

        return $mapper;
    }

    /**
     * @param string $group  The group as it appears in the token: a name, or a path like "/staff/it"
     * @param string[] $roles
     */
    public function withGroup(string $group, array $roles): self
    {
        $mapper = clone $this;
        $mapper->groups[$group] = array_merge($this->groups[$group] ?? [], $roles);

        return $mapper;
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
     * @param mixed $value
     *
     * @return array<mixed>
     */
    private static function table($value, string $option): array
    {
        if (!is_array($value)) {
            throw new ConfigurationException(sprintf('The role mapping "%s" must be a map.', $option));
        }

        return $value;
    }

    /**
     * @param mixed $value
     *
     * @return string[]
     */
    private static function roleList($value, string $option): array
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
