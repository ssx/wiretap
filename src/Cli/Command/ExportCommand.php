<?php

declare(strict_types=1);

namespace Ssx\Wiretap\Cli\Command;

use Ssx\Wiretap\Cli\Input;
use Ssx\Wiretap\Cli\Output;
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
            $this->output->write(Output::cleanJson($json) . PHP_EOL);

            return 0;
        }

        if (!$this->writePrivately($destination, $json)) {
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

    /**
     * Write the export owner-only, before any of it reaches the disk.
     *
     * A HAR holds the same request and response bodies the capture files do,
     * and those are written 0600 into a 0700 directory for a reason.
     * file_put_contents created it at whatever the umask allowed — 0644 on
     * the usual 0022 — so every account on the host could read it, and an
     * existing file kept whatever mode it already had. Wrappers that chmod
     * afterwards leave the window open while the data is written.
     *
     * The file is created under a 0077 umask, opened without truncating, and
     * checked to be the file at that path rather than a symlink's target
     * before it is tightened, emptied and written.
     */
    private function writePrivately(string $path, string $contents): bool
    {
        if (is_link($path)) {
            return false;
        }

        $umask = umask(0o077);

        try {
            $handle = @fopen($path, 'cb');
        } finally {
            umask($umask);
        }

        if ($handle === false) {
            return false;
        }

        try {
            $opened = fstat($handle);
            $atPath = @lstat($path);

            if ($opened === false || $atPath === false
                || $opened['ino'] !== $atPath['ino'] || $opened['dev'] !== $atPath['dev']
                || !is_file($path)) {
                return false;
            }

            if (!@chmod($path, 0o600) || !ftruncate($handle, 0)) {
                return false;
            }

            $written = 0;
            $total = strlen($contents);

            while ($written < $total) {
                $result = fwrite($handle, substr($contents, $written));

                if ($result === false || $result === 0) {
                    return false;
                }

                $written += $result;
            }

            return fflush($handle);
        } finally {
            fclose($handle);
        }
    }
}
