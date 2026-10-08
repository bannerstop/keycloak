<?php

declare(strict_types=1);

namespace Bannerstop\Keycloak\Token;

use Bannerstop\Keycloak\Exception\HttpException;

/**
 * The tokens of one token endpoint response.
 */
final class TokenSet
{
    /** @var string */
    private $accessToken;

    /** @var int|null */
    private $expiresAt;

    /** @var string|null */
    private $refreshToken;

    /** @var int|null */
    private $refreshExpiresAt;

    /** @var string|null */
    private $idToken;

    public function __construct(string $accessToken, ?int $expiresAt, ?string $refreshToken = null, ?int $refreshExpiresAt = null, ?string $idToken = null)
    {
        $this->accessToken = $accessToken;
        $this->expiresAt = $expiresAt;
        $this->refreshToken = $refreshToken;
        $this->refreshExpiresAt = $refreshExpiresAt;
        $this->idToken = $idToken;
    }

    /**
     * @param array<mixed> $response
     */
    public static function fromResponse(array $response, int $now): self
    {
        if (!isset($response['access_token']) || !is_string($response['access_token']) || '' === $response['access_token']) {
            throw new HttpException('The token endpoint returned no access token.');
        }
        $lifetime = static function (string $field) use ($response, $now): ?int {
            return isset($response[$field]) && is_numeric($response[$field]) && (int) $response[$field] > 0 ? $now + (int) $response[$field] : null;
        };
        $string = static function (string $field) use ($response): ?string {
            return isset($response[$field]) && is_string($response[$field]) && '' !== $response[$field] ? $response[$field] : null;
        };

        return new self($response['access_token'], $lifetime('expires_in'), $string('refresh_token'), $lifetime('refresh_expires_in'), $string('id_token'));
    }

    /**
     * @param array<mixed> $data
     */
    public static function fromArray(array $data): self
    {
        return new self(
            (string) ($data['access_token'] ?? ''),
            isset($data['expires_at']) ? (int) $data['expires_at'] : null,
            isset($data['refresh_token']) ? (string) $data['refresh_token'] : null,
            isset($data['refresh_expires_at']) ? (int) $data['refresh_expires_at'] : null,
            isset($data['id_token']) ? (string) $data['id_token'] : null
        );
    }

    /**
     * For storing the set in a session. Treat the result like a password.
     *
     * @return array<string, string|int|null>
     */
    public function toArray(): array
    {
        return [
            'access_token' => $this->accessToken,
            'expires_at' => $this->expiresAt,
            'refresh_token' => $this->refreshToken,
            'refresh_expires_at' => $this->refreshExpiresAt,
            'id_token' => $this->idToken,
        ];
    }

    public function getAccessToken(): string
    {
        return $this->accessToken;
    }

    public function getExpiresAt(): ?int
    {
        return $this->expiresAt;
    }

    public function getRefreshToken(): ?string
    {
        return $this->refreshToken;
    }

    public function getRefreshExpiresAt(): ?int
    {
        return $this->refreshExpiresAt;
    }

    public function getIdToken(): ?string
    {
        return $this->idToken;
    }

    public function isExpired(int $now, int $leeway = 0): bool
    {
        return null !== $this->expiresAt && $this->expiresAt <= $now + $leeway;
    }

    /**
     * @return array<string, mixed>
     */
    public function __debugInfo()
    {
        return [
            'accessToken' => '***',
            'expiresAt' => $this->expiresAt,
            'refreshToken' => null === $this->refreshToken ? null : '***',
            'refreshExpiresAt' => $this->refreshExpiresAt,
            'idToken' => null === $this->idToken ? null : '***',
        ];
    }
}
