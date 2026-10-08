<?php

declare(strict_types=1);

namespace Bannerstop\Keycloak\Admin;

use Bannerstop\Keycloak\Exception\HttpException;
use Bannerstop\Keycloak\KeycloakClient;

/**
 * Reads users of the realm through the admin REST API, e.g. to sync an
 * application's user table. The client needs a service account with the
 * realm-management role "view-users".
 */
final class UserDirectory
{
    private const PAGE_SIZE = 100;

    /** @var KeycloakClient */
    private $client;

    public function __construct(KeycloakClient $serviceAccountClient)
    {
        $this->client = $serviceAccountClient;
    }

    /**
     * All users, page by page.
     *
     * @param string|null $search Matches username, e-mail, first or last name
     *
     * @return \Generator<DirectoryUser>
     *
     * @throws HttpException
     */
    public function users(?string $search = null): \Generator
    {
        $first = 0;
        do {
            $query = ['first' => $first, 'max' => self::PAGE_SIZE, 'briefRepresentation' => 'true'];
            if (null !== $search) {
                $query['search'] = $search;
            }
            $page = $this->client->getAdminResource('users', $query);
            foreach ($page as $representation) {
                $user = is_array($representation) ? DirectoryUser::fromArray($representation) : null;
                if (null !== $user) {
                    yield $user;
                }
            }
            $first += self::PAGE_SIZE;
        } while (self::PAGE_SIZE === count($page));
    }

    /**
     * @throws HttpException
     */
    public function find(string $id): ?DirectoryUser
    {
        try {
            return DirectoryUser::fromArray($this->client->getAdminResource('users/' . rawurlencode($id)));
        } catch (HttpException $exception) {
            if (404 === $exception->getStatusCode()) {
                return null;
            }
            throw $exception;
        }
    }

    /**
     * Group memberships of a user, as paths like "/staff/it".
     *
     * @return string[]
     *
     * @throws HttpException
     */
    public function groupsOf(string $id): array
    {
        $groups = [];
        foreach ($this->client->getAdminResource('users/' . rawurlencode($id) . '/groups', ['briefRepresentation' => 'true']) as $group) {
            if (is_array($group) && isset($group['path']) && is_string($group['path'])) {
                $groups[] = $group['path'];
            }
        }

        return $groups;
    }
}
