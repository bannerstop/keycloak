<?php

declare(strict_types=1);

namespace Bannerstop\Keycloak;

use Bannerstop\Keycloak\Exception\ConfigurationException;
use Bannerstop\Keycloak\Jwt\Algorithm;
use Uri\Rfc3986\Uri;

/**
 * Connection settings for one client of one realm.
 *
 * The server URL and the realm are kept apart, so that the issuer and the
 * admin API URL can both be derived without parsing one from the other.
 */
final readonly class KeycloakConfig
{
    private string $serverUrl;
    private string $realm;
    private string $clientId;
    private ?string $clientSecret;

    /** @var string[] */
    private array $scopes;

    /** @var Algorithm[] */
    private array $allowedAlgorithms;
    private int $leeway;
    private int $metadataTtl;

    /**
     * @param string      $serverUrl         Base URL of the Keycloak server, e.g. https://sso.example.com
     * @param string|null $clientSecret      Null for public clients, which then rely on PKCE alone
     * @param string[]    $scopes            "openid" is always added
     * @param Algorithm[] $allowedAlgorithms Signature algorithms tokens may use
     * @param int         $leeway            Seconds of clock skew tolerated when checking exp, nbf and iat
     * @param int         $metadataTtl       Seconds the discovery document and the key set are cached
     */
    public function __construct(
        string $serverUrl,
        string $realm,
        string $clientId,
        #[\SensitiveParameter] ?string $clientSecret = null,
        array $scopes = ['openid', 'email', 'profile'],
        array $allowedAlgorithms = [Algorithm::RS256],
        int $leeway = 30,
        int $metadataTtl = 3600,
    ) {
        $uri = Uri::parse($serverUrl);
        if (null === $uri || !in_array($uri->getScheme(), ['https', 'http'], true) || null === $uri->getHost()) {
            throw new ConfigurationException('The Keycloak server URL must be an absolute http(s) URL.');
        }
        $serverUrl = rtrim($serverUrl, '/');
        if ('' === $realm || '' === $clientId) {
            throw new ConfigurationException('The realm and the client id must not be empty.');
        }
        if ('' === $clientSecret) {
            $clientSecret = null;
        }
        foreach ($allowedAlgorithms as $algorithm) {
            if (!$algorithm instanceof Algorithm) {
                throw new ConfigurationException('Allowed algorithms must be Algorithm cases.');
            }
        }
        if ([] === $allowedAlgorithms) {
            throw new ConfigurationException('At least one signature algorithm must be allowed.');
        }
        if ($leeway < 0 || $leeway > 300) {
            throw new ConfigurationException('The leeway must be between 0 and 300 seconds.');
        }

        $this->serverUrl = $serverUrl;
        $this->realm = $realm;
        $this->clientId = $clientId;
        $this->clientSecret = $clientSecret;
        $this->scopes = array_values(array_unique(array_merge(['openid'], $scopes)));
        $this->allowedAlgorithms = array_values($allowedAlgorithms);
        $this->leeway = $leeway;
        $this->metadataTtl = max(60, $metadataTtl);
    }

    /**
     * Builds the configuration from a plain array, as it comes from a framework
     * config file. Keys: server_url, realm, client_id, client_secret, scopes,
     * allowed_algorithms, leeway, metadata_ttl.
     *
     * @param array<string, mixed> $options
     */
    public static function fromArray(array $options): self
    {
        foreach (['server_url', 'realm', 'client_id'] as $required) {
            if (!isset($options[$required]) || !is_string($options[$required])) {
                throw new ConfigurationException(sprintf('The option "%s" is required.', $required));
            }
        }

        return new self(
            $options['server_url'],
            $options['realm'],
            $options['client_id'],
            isset($options['client_secret']) ? (string) $options['client_secret'] : null,
            isset($options['scopes']) ? (array) $options['scopes'] : ['openid', 'email', 'profile'],
            self::algorithms($options['allowed_algorithms'] ?? [Algorithm::RS256]),
            isset($options['leeway']) ? (int) $options['leeway'] : 30,
            isset($options['metadata_ttl']) ? (int) $options['metadata_ttl'] : 3600
        );
    }

    public function getServerUrl(): string
    {
        return $this->serverUrl;
    }

    public function getRealm(): string
    {
        return $this->realm;
    }

    public function getIssuer(): string
    {
        return $this->serverUrl . '/realms/' . rawurlencode($this->realm);
    }

    public function getAdminUrl(): string
    {
        return $this->serverUrl . '/admin/realms/' . rawurlencode($this->realm);
    }

    public function getClientId(): string
    {
        return $this->clientId;
    }

    public function getClientSecret(): ?string
    {
        return $this->clientSecret;
    }

    public function isConfidential(): bool
    {
        return null !== $this->clientSecret;
    }

    /**
     * @return string[]
     */
    public function getScopes(): array
    {
        return $this->scopes;
    }

    /**
     * @return Algorithm[]
     */
    public function getAllowedAlgorithms(): array
    {
        return $this->allowedAlgorithms;
    }

    public function getLeeway(): int
    {
        return $this->leeway;
    }

    public function getMetadataTtl(): int
    {
        return $this->metadataTtl;
    }

    /**
     * Keeps the secret out of var_dump() and debug output.
     *
     * @return array<string, mixed>
     */
    public function __debugInfo(): array
    {
        return [
            'serverUrl' => $this->serverUrl,
            'realm' => $this->realm,
            'clientId' => $this->clientId,
            'clientSecret' => null === $this->clientSecret ? null : '***',
            'scopes' => $this->scopes,
            'allowedAlgorithms' => array_column($this->allowedAlgorithms, 'value'),
            'leeway' => $this->leeway,
            'metadataTtl' => $this->metadataTtl,
        ];
    }

    /**
     * Algorithms from configuration files arrive as names like "RS256".
     *
     * @return Algorithm[]
     */
    private static function algorithms(mixed $algorithms): array
    {
        if (!is_array($algorithms)) {
            throw new ConfigurationException('The option "allowed_algorithms" must be a list.');
        }

        return array_map(static fn (mixed $algorithm): Algorithm => match (true) {
            $algorithm instanceof Algorithm => $algorithm,
            is_string($algorithm) => Algorithm::tryFrom($algorithm) ?? throw new ConfigurationException(sprintf('The signature algorithm "%s" is not supported.', $algorithm)),
            default => throw new ConfigurationException('Signature algorithms must be given by name.'),
        }, array_values($algorithms));
    }
}
