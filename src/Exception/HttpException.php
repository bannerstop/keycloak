<?php

declare(strict_types=1);

namespace Bannerstop\Keycloak\Exception;

class HttpException extends \RuntimeException implements KeycloakException
{
    public function __construct(
        string $message,
        private readonly ?int $statusCode = null,
        ?\Throwable $previous = null,
    ) {
        parent::__construct($message, 0, $previous);
    }

    /**
     * Null when no response was received at all.
     */
    public function getStatusCode(): ?int
    {
        return $this->statusCode;
    }
}
