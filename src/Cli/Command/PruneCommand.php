<?php

declare(strict_types=1);

namespace Ssx\Wiretap\Cli\Command;

use Ssx\Wiretap\Cli\Input;

/**
 * Delete logs past a retention window.
 *
 * This ships as a command rather than as advice in a README because retention
 * is a compliance obligation: captured payloads are personal data, and Article
 * 5(1)(e) storage limitation applies to them.
 */
final class PruneCommand extends AbstractCommand
{
    public function handle(Input $input): int
    {
        $window = (string) $input->option('older-than', '7d');

        // A retention window needs a unit. A bare number was read as a Unix
        // timestamp, so `--older-than=7` meant "before 1970" and deleted
        // nothing while reporting success.
        $cutoff = is_numeric(trim($window)) ? null : $this->relativeTime($window);

        if ($cutoff === null) {
            $this->output->line($this->output->red("Could not read '{$window}'. Try --older-than=7d"));

            return 1;
        }

        $dryRun = $input->flag('dry-run');
        $deleted = 0;
        $bytes = 0;

        foreach ($this->reader->files() as $file) {
            $modified = @filemtime($file);

            if ($modified === false || $modified >= $cutoff) {
                continue;
            }

            $size = (int) (@filesize($file) ?: 0);

            if ($dryRun) {
                $this->output->line($this->output->dim('would delete ') . $file);
            } elseif (@unlink($file)) {
                $this->output->line($this->output->dim('deleted ') . $file);
            } else {
                $this->output->line($this->output->red('could not delete ') . $file);

                continue;
            }

            ++$deleted;
            $bytes += $size;
        }

        $this->output->line(sprintf(
            '%s %d file%s (%s)',
            $dryRun ? 'Would remove' : $this->output->green('Removed'),
            $deleted,
            $deleted === 1 ? '' : 's',
            $this->humanBytes($bytes),
        ));

        return 0;
    }

    private function humanBytes(int $bytes): string
    {
        $units = ['B', 'KB', 'MB', 'GB'];
        $i = 0;
        $value = (float) $bytes;

        while ($value >= 1024 && $i < count($units) - 1) {
            $value /= 1024;
            ++$i;
        }

        return round($value, 1) . ' ' . $units[$i];
    }
}
