<?php

declare(strict_types=1);

namespace Ssx\Wiretap\Cli\Command;

use Ssx\Wiretap\Cli\Input;
use Ssx\Wiretap\Export\HarExporter;

final class ExportCommand extends AbstractCommand
{
    public function handle(Input $input): int
    {
        $exchanges = iterator_to_array($this->reader->query($this->queryFrom($input, 200)), false);

        if ($exchanges === []) {
            return $this->noResults();
        }

        // HAR viewers expect oldest-first, matching the order a browser would
        // have recorded them.
        $exchanges = array_reverse($exchanges);

        $json = (new HarExporter())->toJson($exchanges, !$input->flag('compact'));
        $destination = $input->option('out');

        if ($destination === null) {
            $this->output->write($json . PHP_EOL);

            return 0;
        }

        if (@file_put_contents($destination, $json) === false) {
            $this->output->line($this->output->red("Could not write {$destination}"));

            return 1;
        }

        $this->output->line(sprintf(
            '%s %d exchanges to %s',
            $this->output->green('Exported'),
            count($exchanges),
            $destination,
        ));
        $this->output->line($this->output->dim('  Open it in Chrome DevTools (Network → import), Proxyman, Insomnia or Postman.'));

        return 0;
    }
}
