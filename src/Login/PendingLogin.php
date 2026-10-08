<?php

declare(strict_types=1);

namespace Bannerstop\Keycloak\Login;

use Bannerstop\Keycloak\Support\Base64Url;

/**
 * The secrets of a started login that the callback has to match: state
 * against CSRF, nonce against replayed ID tokens, the PKCE verifier against
 * stolen authorization codes.
 */
final readonly class PendingLogin
{
    public function __construct(
        private string $state,
        private string $nonce,
        #[\SensitiveParameter] private string $codeVerifier,
        private string $redirectUri,
        private ?string $returnTo,
        private int $expiresAt,
    ) {
    }

    /**
     * @param string|null $returnTo Where the application wants to send the user afterwards.
     *                              It is stored as given; validate it before redirecting.
     */
    public static function start(string $redirectUri, ?string $returnTo, int $now, int $lifetime = 600): self
    {
        return new self(
            Base64Url::encode(random_bytes(32)),
            Base64Url::encode(random_bytes(32)),
            Base64Url::encode(random_bytes(48)),
            $redirectUri,
            $returnTo,
            $now + $lifetime
        );
    }

    /**
     * @param array<mixed> $data
     */
    public static function fromArray(array $data): ?self
    {
        foreach (['state', 'nonce', 'code_verifier', 'redirect_uri'] as $field) {
            if (!isset($data[$field]) || !is_string($data[$field]) || '' === $data[$field]) {
                return null;
            }
        }
        if (!isset($data['expires_at']) || !is_int($data['expires_at'])) {
            return null;
        }
        $returnTo = isset($data['return_to']) && is_string($data['return_to']) ? $data['return_to'] : null;

        return new self($data['state'], $data['nonce'], $data['code_verifier'], $data['redirect_uri'], $returnTo, $data['expires_at']);
    }

    /**
     * @return array<string, string|int|null>
     */
    public function toArray(): array
    {
        return [
            'state' => $this->state,
            'nonce' => $this->nonce,
            'code_verifier' => $this->codeVerifier,
            'redirect_uri' => $this->redirectUri,
            'return_to' => $this->returnTo,
            'expires_at' => $this->expiresAt,
        ];
    }

    public function getState(): string
    {
        return $this->state;
    }

    public function getNonce(): string
    {
        return $this->nonce;
    }

    public function getCodeVerifier(): string
    {
        return $this->codeVerifier;
    }

    public function getCodeChallenge(): string
    {
        return Base64Url::encode(hash('sha256', $this->codeVerifier, true));
    }

    public function getRedirectUri(): string
    {
        return $this->redirectUri;
    }

    public function getReturnTo(): ?string
    {
        return $this->returnTo;
    }

    public function getExpiresAt(): int
    {
        return $this->expiresAt;
    }

    public function isExpired(int $now): bool
    {
        return $this->expiresAt <= $now;
    }
}
