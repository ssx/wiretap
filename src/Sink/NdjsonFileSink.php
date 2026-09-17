<?php

declare(strict_types=1);

namespace Ssx\Wiretap\Sink;

use Ssx\Wiretap\Contract\ExchangeSink;
use Ssx\Wiretap\Exchange;

/**
 * Appends one JSON object per line.
 *
 * Writes take an exclusive lock. O_APPEND is atomic only up to PIPE_BUF —
 * 4096 bytes on Linux — and a record carrying a 64 KiB body will interleave
 * with a concurrent writer without one. Capping records below PIPE_BUF
 * instead is not a real option, so the lock is the cost of doing business.
 *
 * This is the default sink because writing to a database inline on a
 * customer-facing request is not acceptable. A separate ingest process tails
 * these files into a queryable store.
 */
final class NdjsonFileSink implements ExchangeSink
{
    public function __construct(
        private readonly string $directory,
        private readonly string $prefix = 'wiretap',
        private readonly int $filePermissions = 0o640,
    ) {
    }

    public function write(Exchange $exchange): void
    {
        $this->writeBatch([$exchange]);
    }

    public function writeBatch(iterable $exchanges): void
    {
        $lines = '';

        foreach ($exchanges as $exchange) {
            $encoded = json_encode($exchange, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_INVALID_UTF8_SUBSTITUTE);

            if ($encoded === false) {
                continue;
            }

            $lines .= $encoded . "\n";
        }

        if ($lines === '') {
            return;
        }

        $this->append($lines);
    }

    private function append(string $lines): void
    {
        // The `@` operator is not enough on its own: PHPUnit and several
        // frameworks install error handlers that fire regardless of
        // suppression, so an unwritable log directory would raise an error
        // from inside the instrumentation. A capture layer must never disturb
        // the application it observes, so failures here are silent by
        // construction rather than by convention.
        set_error_handler(static fn (): bool => true);

        try {
            if (!is_dir($this->directory) && !@mkdir($this->directory, 0o750, true) && !is_dir($this->directory)) {
                return;
            }

            $path = $this->currentFile();
            $new = !file_exists($path);

            $handle = @fopen($path, 'ab');

            if ($handle === false) {
                return;
            }

            try {
                if (flock($handle, LOCK_EX)) {
                    fwrite($handle, $lines);
                    fflush($handle);
                    flock($handle, LOCK_UN);
                }
            } finally {
                fclose($handle);
            }

            if ($new) {
                @chmod($path, $this->filePermissions);
            }
        } catch (\Throwable) {
            // See MultiSink: never propagate into the application.
        } finally {
            restore_error_handler();
        }
    }

    public function currentFile(): string
    {
        return sprintf('%s/%s-%s.ndjson', rtrim($this->directory, '/'), $this->prefix, gmdate('Y-m-d'));
    }
}
