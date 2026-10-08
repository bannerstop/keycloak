<?php

declare(strict_types=1);

namespace Bannerstop\Keycloak\Exception;

/**
 * A browser login that could not be completed. The reason is meant for the
 * application to pick a message; the exception message is for logs only and
 * never contains tokens.
 */
class LoginException extends \RuntimeException implements KeycloakException
{
    public function __construct(
        private readonly LoginFailure $reason,
        string $message,
        ?\Throwable $previous = null,
    ) {
        parent::__construct($message, 0, $previous);
    }

    public function getReason(): LoginFailure
    {
        return $this->reason;
    }
}
