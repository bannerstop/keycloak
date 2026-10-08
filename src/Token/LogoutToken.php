<?php

declare(strict_types=1);

namespace Bannerstop\Keycloak\Token;

/**
 * A verified back-channel logout token: Keycloak ended this session, or all
 * sessions of this user that started before the token was issued.
 */
final readonly class LogoutToken
{
    public function __construct(
        private ?string $subject,
        private ?string $sessionId,
        private int $issuedAt,
        private string $tokenId,
    ) {
    }

    public static function fromClaims(Claims $claims): self
    {
        return new self($claims->getString('sub'), $claims->getString('sid'), (int) $claims->getInt('iat'), (string) $claims->getString('jti'));
    }

    public function getSubject(): ?string
    {
        return $this->subject;
    }

    /**
     * The Keycloak session ("sid"), null if the token ends every session of the subject.
     */
    public function getSessionId(): ?string
    {
        return $this->sessionId;
    }

    public function getIssuedAt(): int
    {
        return $this->issuedAt;
    }

    /**
     * The "jti", unique per token, for replay detection.
     */
    public function getTokenId(): string
    {
        return $this->tokenId;
    }
}
