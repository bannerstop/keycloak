<?php

declare(strict_types=1);

namespace Bannerstop\Keycloak\Jwt;

use Bannerstop\Keycloak\Discovery\MetadataProvider;
use Bannerstop\Keycloak\Http\JsonHttpClient;
use Bannerstop\Keycloak\KeycloakConfig;
use Bannerstop\Keycloak\Support\Cache;
use Psr\Clock\ClockInterface;

/**
 * Loads and caches the realm's JWKS. After a key rotation the first token
 * with an unknown kid triggers a reload, at most once per minute, so that
 * forged kids cannot turn every request into a call to Keycloak.
 *
 * @internal
 */
final class KeySetProvider
{
    private const MIN_REFRESH_INTERVAL = 60;

    /** @var KeycloakConfig */
    private $config;

    /** @var MetadataProvider */
    private $metadata;

    /** @var JsonHttpClient */
    private $http;

    /** @var Cache */
    private $cache;

    /** @var ClockInterface */
    private $clock;

    public function __construct(KeycloakConfig $config, MetadataProvider $metadata, JsonHttpClient $http, Cache $cache, ClockInterface $clock)
    {
        $this->config = $config;
        $this->metadata = $metadata;
        $this->http = $http;
        $this->cache = $cache;
        $this->clock = $clock;
    }

    public function find(?string $keyId, string $algorithm): ?JsonWebKey
    {
        $cached = $this->cache->get($this->cacheKey());
        if (is_array($cached) && isset($cached['jwks'], $cached['fetched_at']) && is_array($cached['jwks'])) {
            $key = KeySet::fromArray($cached['jwks'])->find($keyId, $algorithm);
            if (null !== $key || $this->now() - (int) $cached['fetched_at'] < self::MIN_REFRESH_INTERVAL) {
                return $key;
            }
        }

        return $this->load()->find($keyId, $algorithm);
    }

    private function load(): KeySet
    {
        $document = $this->http->get($this->metadata->get()->getJwksUri());
        $this->cache->set($this->cacheKey(), ['jwks' => $document, 'fetched_at' => $this->now()], $this->config->getMetadataTtl());

        return KeySet::fromArray($document);
    }

    private function cacheKey(): string
    {
        return 'bannerstop_keycloak.jwks.' . sha1($this->config->getIssuer());
    }

    private function now(): int
    {
        return $this->clock->now()->getTimestamp();
    }
}
