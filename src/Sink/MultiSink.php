<?php

declare(strict_types=1);

namespace Ssx\Wiretap\Sink;

use Ssx\Wiretap\Contract\ExchangeSink;
use Ssx\Wiretap\Exchange;

/**
 * Fans out to several sinks. One failing sink must not stop the others, and
 * must not propagate into the application.
 */
final readonly class MultiSink implements ExchangeSink
{
    /** @var list<ExchangeSink> */
    private array $sinks;

    public function __construct(ExchangeSink ...$sinks)
    {
        $this->sinks = array_values($sinks);
    }

    public function write(Exchange $exchange): void
    {
        foreach ($this->sinks as $sink) {
            try {
                $sink->write($exchange);
            } catch (\Throwable) {
                // Deliberately swallowed. A logging tool that breaks the
                // application it observes is worse than one that loses a
                // record.
            }
        }
    }

    public function writeBatch(iterable $exchanges): void
    {
        $buffered = is_array($exchanges) ? $exchanges : iterator_to_array($exchanges, false);

        foreach ($this->sinks as $sink) {
            try {
                $sink->writeBatch($buffered);
            } catch (\Throwable) {
            }
        }
    }
}
