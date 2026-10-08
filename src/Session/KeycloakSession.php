<?php

declare(strict_types=1);

namespace Bannerstop\Keycloak\Session;

use Bannerstop\Keycloak\Login\LoginResult;
use Bannerstop\Keycloak\Token\TokenSet;

/**
 * What an application keeps in its own session about the Keycloak login
 * behind it: the tokens, the Keycloak session id and when it was last checked.
 * Treat it like a password: store it server-side only.
 */
final class KeycloakSession
{
    public function __construct(
        private string $subject,
        private ?string $sessionId,
        private TokenSet $tokens,
        private int $loggedInAt,
        private int $checkedAt,
    ) {
    }

    public static function fromLogin(LoginResult $result, int $now): self
    {
        $identity = $result->getIdentity();

        return new self($identity->getSubject(), $identity->getSessionId(), $result->getTokens(), $now, $now);
    }

    /**
     * @param array<mixed> $data
     */
    public static function fromArray(array $data): ?self
    {
        if (!is_string($data['subject'] ?? null) || !is_array($data['tokens'] ?? null) || !is_int($data['logged_in_at'] ?? null) || !is_int($data['checked_at'] ?? null)) {
            return null;
        }

        return new self($data['subject'], is_string($data['session_id'] ?? null) ? $data['session_id'] : null, TokenSet::fromArray($data['tokens']), $data['logged_in_at'], $data['checked_at']);
    }

    /**
     * @return array<string, mixed>
     */
    public function toArray(): array
    {
        return [
            'subject' => $this->subject,
            'session_id' => $this->sessionId,
            'tokens' => $this->tokens->toArray(),
            'logged_in_at' => $this->loggedInAt,
            'checked_at' => $this->checkedAt,
        ];
    }

    public function withRefreshedTokens(TokenSet $tokens, int $now): self
    {
        // A refresh response may leave out the ID token or the refresh token; keep the old ones then.
        $merged = new TokenSet(
            $tokens->getAccessToken(),
            $tokens->getExpiresAt(),
            $tokens->getRefreshToken() ?? $this->tokens->getRefreshToken(),
            null !== $tokens->getRefreshToken() ? $tokens->getRefreshExpiresAt() : $this->tokens->getRefreshExpiresAt(),
            $tokens->getIdToken() ?? $this->tokens->getIdToken(),
        );

        return new self($this->subject, $this->sessionId, $merged, $this->loggedInAt, $now);
    }

    public function withCheckedAt(int $now): self
    {
        return new self($this->subject, $this->sessionId, $this->tokens, $this->loggedInAt, $now);
    }

    public function getSubject(): string
    {
        return $this->subject;
    }

    /**
     * Keycloak's session id ("sid" of the ID token), which back-channel logout tokens name.
     */
    public function getSessionId(): ?string
    {
        return $this->sessionId;
    }

    public function getTokens(): TokenSet
    {
        return $this->tokens;
    }

    public function getLoggedInAt(): int
    {
        return $this->loggedInAt;
    }

    public function getCheckedAt(): int
    {
        return $this->checkedAt;
    }

    /**
     * @return array<string, mixed>
     */
    public function __debugInfo(): array
    {
        return ['subject' => $this->subject, 'sessionId' => $this->sessionId, 'tokens' => '***', 'loggedInAt' => $this->loggedInAt, 'checkedAt' => $this->checkedAt];
    }
}
