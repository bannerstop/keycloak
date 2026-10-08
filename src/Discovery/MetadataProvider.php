<?php

declare(strict_types=1);

namespace Bannerstop\Keycloak\Discovery;

use Bannerstop\Keycloak\Exception\HttpException;
use Bannerstop\Keycloak\Http\JsonHttpClient;
use Bannerstop\Keycloak\KeycloakConfig;
use Bannerstop\Keycloak\Support\Cache;

/**
 * Loads and caches the discovery document of the configured realm.
 *
 * @internal
 */
final class MetadataProvider
{
    /** @var KeycloakConfig */
    private $config;

    /** @var JsonHttpClient */
    private $http;

    /** @var Cache */
    private $cache;

    public function __construct(KeycloakConfig $config, JsonHttpClient $http, Cache $cache)
    {
        $this->config = $config;
        $this->http = $http;
        $this->cache = $cache;
    }

    public function get(): ProviderMetadata
    {
        $key = 'bannerstop_keycloak.metadata.' . sha1($this->config->getIssuer());
        $cached = $this->cache->get($key);
        if (is_array($cached)) {
            return ProviderMetadata::fromArray($cached);
        }

        $metadata = ProviderMetadata::fromArray($this->http->get($this->config->getIssuer() . '/.well-known/openid-configuration'));
        // A document for another issuer would make every later issuer check meaningless.
        if ($metadata->getIssuer() !== $this->config->getIssuer()) {
            throw new HttpException(sprintf('The discovery document belongs to the issuer "%s", expected "%s".', $metadata->getIssuer(), $this->config->getIssuer()));
        }
        $this->cache->set($key, $metadata->toArray(), $this->config->getMetadataTtl());

        return $metadata;
    }
}
