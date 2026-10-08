<?php

declare(strict_types=1);

namespace Bannerstop\Keycloak\Exception;

/**
 * Why a browser login failed. The values are stable and meant for
 * translation keys or log fields.
 */
enum LoginFailure: string
{
    /** The callback does not belong to a login started in this session, or it expired. */
    case StateMismatch = 'state_mismatch';

    /** The user cancelled at the identity provider. */
    case Cancelled = 'cancelled';

    /** The identity provider reported an error or could not be reached. */
    case ProviderError = 'provider_error';

    /** The tokens returned by the identity provider failed verification. */
    case InvalidToken = 'invalid_token';

    /** The identity was verified, but an IdentityPolicy rejected it. */
    case NotAllowed = 'not_allowed';
}
