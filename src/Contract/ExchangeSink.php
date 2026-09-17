<?php

declare(strict_types=1);

namespace Ssx\Wiretap\Contract;

use Ssx\Wiretap\Exchange;

/**
 * Somewhere completed exchanges are written.
 *
 * Write-only on purpose. A file or PSR-3 sink cannot answer queries, and
 * requiring every sink to implement search would make the simple ones
 * impossible. Reading is ExchangeReader's job.
 *
 * Implementations must not throw. A logging tool that breaks the application
 * it is observing is worse than one that loses a record, so failures are
 * swallowed and surfaced through diagnostics instead.
 */
interface ExchangeSink
{
    public function write(Exchange $exchange): void;

    /**
     * @param iterable<Exchange> $exchanges
     */
    public function writeBatch(iterable $exchanges): void;
}
