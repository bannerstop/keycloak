<?php

declare(strict_types=1);

namespace Bannerstop\Keycloak\Support;

use Psr\Clock\ClockInterface;

final class SystemClock implements ClockInterface
{
    #[\Override]
    public function now(): \DateTimeImmutable
    {
        return new \DateTimeImmutable();
    }
}
