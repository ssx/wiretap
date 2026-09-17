<?php

declare(strict_types=1);

namespace Ssx\Wiretap\Cli\Command;

use Ssx\Wiretap\Cli\Input;

final class ListCommand extends AbstractCommand
{
    public function handle(Input $input): int
    {
        $exchanges = iterator_to_array($this->reader->query($this->queryFrom($input)), false);

        if ($exchanges === []) {
            return $this->noResults();
        }

        $o = $this->output;

        $o->line();
        $o->line($o->dim(sprintf(
            '  %-3s %-14s %-6s %-6s %8s  %s',
            '#', 'WHEN', 'METHOD', 'STATUS', 'TIME', 'URI',
        )));

        foreach ($exchanges as $i => $exchange) {
            // Pad the plain text first: colour codes are invisible on screen
            // but str_pad counts them, so padding after colouring misaligns
            // every row that has a different status width.
            $status = str_pad((string) ($exchange->status ?? 'ERR'), 6);
            $status = str_replace(
                (string) ($exchange->status ?? 'ERR'),
                $o->statusColour($exchange->status),
                $status,
            );

            $o->line(sprintf(
                '  %-3d %-14s %-6s %s %8s  %s',
                $i + 1,
                $this->relativeAge($exchange->startedAt),
                $exchange->method,
                $status,
                $this->formatMs($exchange->timings->total),
                $this->shortUri($exchange->uri),
            ));

            if ($exchange->error !== null) {
                $o->line('      ' . $o->red('└ ' . $exchange->error->message));
            }
        }

        $o->line();
        $o->line($o->dim('  wiretap show <#>   for the full request and response'));
        $o->line();

        return 0;
    }
}
