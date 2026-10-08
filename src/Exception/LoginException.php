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
    /** The callback does not belong to a login started in this session, or it expired. */
    public const STATE_MISMATCH = 'state_mismatch';

    /** The user cancelled at the identity provider. */
    public const CANCELLED = 'cancelled';

    /** The identity provider reported an error or could not be reached. */
    public const PROVIDER_ERROR = 'provider_error';

    /** The tokens returned by the identity provider failed verification. */
    public const INVALID_TOKEN = 'invalid_token';

    /** The identity was verified, but an IdentityPolicy rejected it. */
    public const NOT_ALLOWED = 'not_allowed';

    /** @var string */
    private $reason;

    public function __construct(string $reason, string $message, ?\Throwable $previous = null)
    {
        parent::__construct($message, 0, $previous);
        $this->reason = $reason;
    }

    public function getReason(): string
    {
        return $this->reason;
    }
}
