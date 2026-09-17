<?php

declare(strict_types=1);

namespace Ssx\Wiretap\Cli\Command;

use Ssx\Wiretap\Cli\Input;
use Ssx\Wiretap\Query\ExchangeQuery;

/**
 * Every outbound call made while handling one inbound request.
 *
 * This is what the correlation id is for, and it is usually the view that
 * answers the question: not "was this call slow" but "what else did we do
 * before it, and which of those was the real problem".
 */
final class TraceCommand extends AbstractCommand
{
    public function handle(Input $input): int
    {
        $correlationId = $input->argument(0);

        if ($correlationId === null) {
            $this->output->line($this->output->red('Which correlation? Try: wiretap trace <correlation-id>'));

            return 1;
        }

        $exchanges = iterator_to_array($this->reader->query(new ExchangeQuery(
            correlationId: $correlationId,
            limit: $input->integer('limit', 200),
            newestFirst: false,
        )), false);

        if ($exchanges === []) {
            $this->output->line($this->output->dim("Nothing recorded for correlation {$correlationId}"));

            return 0;
        }

        usort($exchanges, static fn ($a, $b): int => $a->sequence <=> $b->sequence ?: $a->startedAt <=> $b->startedAt);

        $o = $this->output;
        $first = $exchanges[0];
        $last = end($exchanges);

        $wallStart = $first->startedAt;
        $wallEnd = $last->startedAt + (($last->timings->total ?? 0) / 1_000_000);
        $span = max($wallEnd - $wallStart, 0.000001);
        $totalUs = array_sum(array_map(static fn ($e): int => $e->timings->total ?? 0, $exchanges));

        $o->line();
        $o->line($o->bold('Correlation ') . $correlationId);
        $o->line($o->dim(sprintf(
            '  %d calls · %s spent waiting on the network · %s',
            count($exchanges),
            $this->formatMs((int) $totalUs),
            $this->relativeAge($wallStart),
        )));
        $o->line();

        $width = 32;

        foreach ($exchanges as $i => $exchange) {
            $offset = $exchange->startedAt - $wallStart;
            $duration = ($exchange->timings->total ?? 0) / 1_000_000;

            $startCol = (int) floor(($offset / $span) * $width);
            $barWidth = max(1, (int) round(($duration / $span) * $width));
            $startCol = min($startCol, $width - 1);
            $barWidth = min($barWidth, $width - $startCol);

            // Build to an exact character count rather than str_pad-ing:
            // the block glyph is three bytes in UTF-8, so byte-based padding
            // leaves every row a different visible width.
            $bar = str_repeat(' ', $startCol)
                . str_repeat('█', $barWidth)
                . str_repeat(' ', max(0, $width - $startCol - $barWidth));

            $status = str_pad((string) ($exchange->status ?? 'ERR'), 4);
            $status = str_replace(
                (string) ($exchange->status ?? 'ERR'),
                $o->statusColour($exchange->status),
                $status,
            );

            $o->line(sprintf(
                '  %-3d %s %s %s %8s  %s',
                $i + 1,
                $o->dim($bar),
                $status,
                str_pad($exchange->method, 6),
                $this->formatMs($exchange->timings->total),
                $this->shortUri($exchange->uri, 44),
            ));
        }

        $o->line();

        return 0;
    }
}
