<?php

declare(strict_types=1);

namespace Bannerstop\Keycloak;

use Bannerstop\Keycloak\Discovery\MetadataProvider;
use Bannerstop\Keycloak\Discovery\ProviderMetadata;
use Bannerstop\Keycloak\Exception\HttpException;
use Bannerstop\Keycloak\Exception\InvalidTokenException;
use Bannerstop\Keycloak\Http\JsonHttpClient;
use Bannerstop\Keycloak\Jwt\KeySetProvider;
use Bannerstop\Keycloak\Jwt\TokenVerifier;
use Bannerstop\Keycloak\Login\PendingLogin;
use Bannerstop\Keycloak\Support\Cache;
use Bannerstop\Keycloak\Support\SystemClock;
use Bannerstop\Keycloak\Token\Claims;
use Bannerstop\Keycloak\Token\TokenSet;
use Psr\Clock\ClockInterface;
use Psr\Http\Client\ClientInterface;
use Psr\Http\Message\RequestFactoryInterface;
use Psr\Http\Message\StreamFactoryInterface;
use Psr\SimpleCache\CacheInterface;

/**
 * The OpenID Connect protocol against one Keycloak client. It holds no user
 * state; LoginFlow adds the session handling of a browser login.
 */
class KeycloakClient
{
    /** Parameters an application may add to the authorization request. */
    private const AUTHORIZATION_PARAMETERS = ['prompt', 'login_hint', 'kc_idp_hint', 'ui_locales', 'max_age', 'acr_values', 'kc_action'];

    /** @var KeycloakConfig */
    private $config;

    /** @var JsonHttpClient */
    private $http;

    /** @var MetadataProvider */
    private $metadata;

    /** @var TokenVerifier */
    private $verifier;

    /** @var ClockInterface */
    private $clock;

    /** @var TokenSet|null */
    private $serviceAccountTokens;

    public function __construct(
        KeycloakConfig $config,
        ClientInterface $httpClient,
        RequestFactoryInterface $requestFactory,
        StreamFactoryInterface $streamFactory,
        ?CacheInterface $cache = null,
        ?ClockInterface $clock = null
    ) {
        $this->config = $config;
        $this->clock = $clock ?? new SystemClock();
        $this->http = new JsonHttpClient($httpClient, $requestFactory, $streamFactory);
        $cacheWrapper = new Cache($cache);
        $this->metadata = new MetadataProvider($config, $this->http, $cacheWrapper);
        $this->verifier = new TokenVerifier($config, new KeySetProvider($config, $this->metadata, $this->http, $cacheWrapper, $this->clock), $this->clock);
    }

    public function getConfig(): KeycloakConfig
    {
        return $this->config;
    }

    public function getMetadata(): ProviderMetadata
    {
        return $this->metadata->get();
    }

    /**
     * @param array<string, string|int> $parameters Optional extras: prompt, login_hint, kc_idp_hint, ui_locales, max_age, acr_values, kc_action
     */
    public function getAuthorizationUrl(PendingLogin $login, array $parameters = []): string
    {
        $unknown = array_diff(array_keys($parameters), self::AUTHORIZATION_PARAMETERS);
        if ([] !== $unknown) {
            throw new \InvalidArgumentException(sprintf('Unsupported authorization parameters: %s.', implode(', ', $unknown)));
        }

        $query = array_merge($parameters, [
            'response_type' => 'code',
            'client_id' => $this->config->getClientId(),
            'redirect_uri' => $login->getRedirectUri(),
            'scope' => implode(' ', $this->config->getScopes()),
            'state' => $login->getState(),
            'nonce' => $login->getNonce(),
            'code_challenge' => $login->getCodeChallenge(),
            'code_challenge_method' => 'S256',
        ]);

        return self::appendQuery($this->getMetadata()->getAuthorizationEndpoint(), $query);
    }

    /**
     * Exchanges the authorization code of a callback for tokens.
     *
     * @throws HttpException
     */
    public function exchangeCode(string $code, PendingLogin $login): TokenSet
    {
        return $this->requestTokens([
            'grant_type' => 'authorization_code',
            'code' => $code,
            'redirect_uri' => $login->getRedirectUri(),
            'code_verifier' => $login->getCodeVerifier(),
        ]);
    }

    /**
     * @throws HttpException
     */
    public function refresh(string $refreshToken): TokenSet
    {
        return $this->requestTokens(['grant_type' => 'refresh_token', 'refresh_token' => $refreshToken]);
    }

    /**
     * Tokens for the client's own service account (client credentials grant).
     *
     * @throws HttpException
     */
    public function requestServiceAccountTokens(): TokenSet
    {
        if (!$this->config->isConfidential()) {
            throw new \LogicException('Only confidential clients have a service account.');
        }

        return $this->requestTokens(['grant_type' => 'client_credentials']);
    }

    /**
     * Verifies the tokens of a login and returns the user. Claims come from
     * the ID token, plus roles and groups from the access token, which is
     * where Keycloak puts them by default.
     *
     * @param string|null $nonce The nonce of the pending login; null only after a refresh
     *
     * @throws InvalidTokenException
     * @throws HttpException         When the signing keys cannot be loaded
     */
    public function getIdentity(TokenSet $tokens, ?string $nonce): Identity
    {
        $idToken = $tokens->getIdToken();
        if (null === $idToken) {
            throw new InvalidTokenException('The token response has no ID token. Is the "openid" scope missing?');
        }
        $claims = $this->verifier->verifyIdToken($idToken, $nonce);

        if (self::isJwt($tokens->getAccessToken())) {
            $accessClaims = $this->verifier->verifyOwnAccessToken($tokens->getAccessToken());
            if ($accessClaims->getString('sub') !== $claims->getString('sub')) {
                throw new InvalidTokenException('The ID token and the access token belong to different users.');
            }
            $claims = $accessClaims->merge($claims);
        }

        return new Identity($claims);
    }

    /**
     * Verifies an access token sent to an API as "Authorization: Bearer ...".
     *
     * @param string|null $audience The audience the token must be issued for; defaults to the client id
     *
     * @throws InvalidTokenException
     * @throws HttpException         When the signing keys cannot be loaded
     */
    public function verifyAccessToken(string $accessToken, ?string $audience = null): Identity
    {
        return new Identity($this->verifier->verifyAccessToken($accessToken, $audience ?? $this->config->getClientId()));
    }

    /**
     * Claims from the userinfo endpoint, for providers or mappers that keep
     * claims out of the tokens.
     *
     * @throws HttpException
     */
    public function getUserInfo(string $accessToken): Claims
    {
        $endpoint = $this->getMetadata()->getUserinfoEndpoint();
        if (null === $endpoint) {
            throw new HttpException('The provider has no userinfo endpoint.');
        }

        return new Claims($this->http->get($endpoint, [], $accessToken));
    }

    /**
     * The URL that ends the Keycloak session (RP-initiated logout). Null if
     * the provider does not support it; then only the local session ends.
     *
     * @param string|null $idToken The ID token of the session; without it Keycloak asks the user to confirm
     */
    public function getLogoutUrl(?string $postLogoutRedirectUri = null, ?string $idToken = null): ?string
    {
        $endpoint = $this->getMetadata()->getEndSessionEndpoint();
        if (null === $endpoint) {
            return null;
        }
        $query = ['client_id' => $this->config->getClientId()];
        if (null !== $idToken) {
            $query['id_token_hint'] = $idToken;
        }
        if (null !== $postLogoutRedirectUri) {
            $query['post_logout_redirect_uri'] = $postLogoutRedirectUri;
        }

        return self::appendQuery($endpoint, $query);
    }

    /**
     * Revokes a refresh token, e.g. on logout from a session that has no
     * browser redirect. Does nothing if the provider has no revocation endpoint.
     *
     * @throws HttpException
     */
    public function revokeRefreshToken(string $refreshToken): void
    {
        $endpoint = $this->getMetadata()->getRevocationEndpoint();
        if (null !== $endpoint) {
            $this->postAsClient($endpoint, ['token' => $refreshToken, 'token_type_hint' => 'refresh_token']);
        }
    }

    /**
     * GET on the realm's admin REST API as the client's service account, e.g.
     * "/users". The service account needs the matching realm-management roles.
     *
     * @param array<string, scalar> $query
     *
     * @return array<mixed>
     *
     * @throws HttpException
     */
    public function getAdminResource(string $path, array $query = []): array
    {
        if (null === $this->serviceAccountTokens || $this->serviceAccountTokens->isExpired($this->now(), 10)) {
            $this->serviceAccountTokens = $this->requestServiceAccountTokens();
        }

        return $this->http->get($this->config->getAdminUrl() . '/' . ltrim($path, '/'), $query, $this->serviceAccountTokens->getAccessToken());
    }

    public function now(): int
    {
        return $this->clock->now()->getTimestamp();
    }

    /**
     * @param array<string, string> $fields
     */
    private function requestTokens(array $fields): TokenSet
    {
        return TokenSet::fromResponse($this->postAsClient($this->getMetadata()->getTokenEndpoint(), $fields), $this->now());
    }

    /**
     * Confidential clients authenticate with HTTP Basic (client_secret_basic),
     * public clients only identify themselves in the body.
     *
     * @param array<string, string> $fields
     *
     * @return array<mixed>
     */
    private function postAsClient(string $endpoint, array $fields): array
    {
        if (!$this->config->isConfidential()) {
            return $this->http->postForm($endpoint, array_merge($fields, ['client_id' => $this->config->getClientId()]));
        }

        return $this->http->postForm($endpoint, $fields, $this->config->getClientId(), $this->config->getClientSecret());
    }

    /**
     * @param array<string, string|int> $query
     */
    private static function appendQuery(string $url, array $query): string
    {
        return $url . (false === strpos($url, '?') ? '?' : '&') . http_build_query($query, '', '&', PHP_QUERY_RFC3986);
    }

    private static function isJwt(string $token): bool
    {
        return 2 === substr_count($token, '.');
    }
}
