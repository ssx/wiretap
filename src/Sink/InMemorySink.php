<?php

declare(strict_types=1);

namespace Ssx\Wiretap\Sink;

use Ssx\Wiretap\Contract\ExchangeSink;
use Ssx\Wiretap\Exchange;

/**
 * Keeps exchanges in memory. Backs the test assertions and the scoped
 * `debug()` helper, and is bounded so a runaway loop cannot exhaust memory.
 */
final class InMemorySink implements ExchangeSink
{
    /** @var list<Exchange> */
    private array $exchanges = [];

    private int $dropped = 0;

    public function __construct(private readonly int $limit = 1000)
    {
    }

    public function write(Exchange $exchange): void
    {
        if (count($this->exchanges) >= $this->limit) {
            ++$this->dropped;

            return;
        }

        $this->exchanges[] = $exchange;
    }

    public function writeBatch(iterable $exchanges): void
    {
        foreach ($exchanges as $exchange) {
            $this->write($exchange);
        }
    }

    /**
     * @return list<Exchange>
     */
    public function all(): array
    {
        return $this->exchanges;
    }

    public function dropped(): int
    {
        return $this->dropped;
    }

    public function clear(): void
    {
        $this->exchanges = [];
        $this->dropped = 0;
    }
}
