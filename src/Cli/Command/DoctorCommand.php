<?php

declare(strict_types=1);

namespace Ssx\Wiretap\Cli\Command;

use Ssx\Wiretap\Cli\Input;
use Ssx\Wiretap\Query\ExchangeQuery;

/**
 * Answers "why is nothing being recorded", which otherwise costs an afternoon.
 *
 * It is also where the intended-use policy is enforced in practice. A tool
 * documented as temporary but behaving identically on day ninety will be left
 * on; the age warning is the only part of that policy that actually runs.
 */
final class DoctorCommand extends AbstractCommand
{
    private const NAG_AFTER_HOURS = 24;

    public function handle(Input $input): int
    {
        $o = $this->output;
        $problems = 0;

        $o->line();
        $o->line($o->bold('wiretap doctor'));
        $o->line();

        $o->line($o->bold('Environment'));
        $this->row('PHP', PHP_VERSION, version_compare(PHP_VERSION, '8.2', '>='));
        // The core package requires only PHP, so an installation without
        // ext-curl is supported — and calling curl_version() to report its
        // absence crashed the command that exists to explain problems.
        $this->row(
            'ext-curl',
            function_exists('curl_version')
                ? (string) (curl_version()['version'] ?? 'unknown')
                : 'not installed',
            function_exists('curl_version'),
        );

        $hasExtension = extension_loaded('opentelemetry');
        $this->row(
            'ext-opentelemetry',
            $hasExtension ? (string) (phpversion('opentelemetry') ?: 'loaded') : 'not installed',
            $hasExtension,
        );

        if (!$hasExtension) {
            ++$problems;
            $o->line($o->dim('    Without it, only Guzzle clients you wire up yourself are captured.'));
            $o->line($o->dim('    Vendor code and raw curl_exec() are invisible. Install:'));
            $o->line($o->dim('      pecl install opentelemetry'));
        }

        $o->line();
        $o->line($o->bold('Storage'));

        $exists = is_dir($this->path);
        $this->row('log directory', $this->path, $exists);

        if (!$exists) {
            ++$problems;
            $o->line($o->dim('    Nothing has been written here yet.'));
            $o->line($o->dim('    Capture is off unless WIRETAP_ENABLED is truthy.'));
        }

        $files = $this->reader->files();
        $bytes = array_sum(array_map(static fn (string $f): int => (int) (@filesize($f) ?: 0), $files));

        $this->row('log files', sprintf('%d (%s)', count($files), $this->humanBytes($bytes)), true);

        $enabled = filter_var(getenv('WIRETAP_ENABLED') ?: 'false', FILTER_VALIDATE_BOOL);
        $this->row('WIRETAP_ENABLED', $enabled ? 'true' : 'false', true);

        $o->line();
        $o->line($o->bold('Recorded traffic'));

        $recent = iterator_to_array($this->reader->query(new ExchangeQuery(limit: 500)), false);

        if ($recent === []) {
            $o->line($o->dim('  Nothing recorded.'));
        } else {
            $hosts = [];
            $failures = 0;

            foreach ($recent as $exchange) {
                $host = $exchange->host() ?? '(unparseable)';
                $hosts[$host] = ($hosts[$host] ?? 0) + 1;

                if ($exchange->failed()) {
                    ++$failures;
                }
            }

            arsort($hosts);

            $this->row('exchanges', (string) count($recent), true);
            $this->row('failures', (string) $failures, $failures === 0);

            $o->line();
            $o->line($o->dim('  Top hosts'));

            foreach (array_slice($hosts, 0, 8, true) as $host => $count) {
                $o->line(sprintf('    %-42s %d', $host, $count));
            }

            $problems += $this->warnIfLeftRunning($files);
        }

        $o->line();

        if ($problems === 0) {
            $o->line($o->green('  Everything checks out.'));
        } else {
            $o->line($o->yellow(sprintf('  %d thing%s to look at above.', $problems, $problems === 1 ? '' : 's')));
        }

        $o->line();

        return 0;
    }

    /**
     * @param list<string> $files
     */
    private function warnIfLeftRunning(array $files): int
    {
        if ($files === []) {
            return 0;
        }

        $oldest = min(array_map(static fn (string $f): int => (int) (@filemtime($f) ?: time()), $files));
        $hours = (int) floor((time() - $oldest) / 3600);

        if ($hours < self::NAG_AFTER_HOURS) {
            return 0;
        }

        $o = $this->output;

        $o->line();
        $o->line($o->yellow(sprintf('  Capture has been on for at least %dh.', $hours)));
        $o->line($o->dim('  Wiretap records complete request and response bodies. It is a debugging'));
        $o->line($o->dim('  tool, not a logging product, and it is neither PCI-DSS nor GDPR'));
        $o->line($o->dim('  compliant on its own. Turn it off when you are done, and run:'));
        $o->line($o->dim('    wiretap prune --older-than=1d'));

        return 1;
    }

    private function row(string $label, string $value, bool $ok): void
    {
        $this->output->line(sprintf(
            '  %s %-22s %s',
            $ok ? $this->output->green('✓') : $this->output->yellow('!'),
            $label,
            $this->output->dim($value),
        ));
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
