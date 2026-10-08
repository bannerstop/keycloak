<?php

declare(strict_types=1);

namespace Bannerstop\Keycloak\Tests\Fixtures;

use Psr\Clock\ClockInterface;

final class FrozenClock implements ClockInterface
{
    public function __construct(
        public int $time,
    ) {
    }

    public function now(): \DateTimeImmutable
    {
        return new \DateTimeImmutable('@' . $this->time);
    }
}
