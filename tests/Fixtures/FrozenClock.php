<?php

declare(strict_types=1);

namespace Bannerstop\Keycloak\Tests\Fixtures;

use Psr\Clock\ClockInterface;

final class FrozenClock implements ClockInterface
{
    /** @var int */
    public $time;

    public function __construct(int $time)
    {
        $this->time = $time;
    }

    public function now(): \DateTimeImmutable
    {
        return new \DateTimeImmutable('@' . $this->time);
    }
}
