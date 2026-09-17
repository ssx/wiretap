<?php

declare(strict_types=1);

namespace Ssx\Wiretap\Sink;

use Ssx\Wiretap\Contract\ExchangeSink;
use Ssx\Wiretap\Exchange;

final class NullSink implements ExchangeSink
{
    public function write(Exchange $exchange): void
    {
    }

    public function writeBatch(iterable $exchanges): void
    {
    }
}
