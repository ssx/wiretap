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
                    // Seek to the real end *after* taking the lock. ftell() on
                    // a handle opened before the lock can sit behind EOF if
                    // another writer appended in between — and the rollback
                    // would then truncate away that writer's committed
                    // records. A crash-safety measure that deletes other
                    // processes' data is worse than the problem it solves.
                    if (fseek($handle, 0, SEEK_END) === 0) {
                        $this->writeAll($handle, $lines);
                        fflush($handle);
                    }

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

    /**
     * Write the whole buffer, or leave the file as it was.
     *
     * fwrite() may write fewer bytes than asked — a full disk is the usual
     * cause. Ignoring that left an incomplete JSON line, and the next append
     * concatenated a record onto it, so one failed write cost two records and
     * left a line no reader could parse. On failure the file is truncated back
     * to where this write started, while the lock is still held.
     *
     * @param resource $handle
     */
    private function writeAll($handle, string $data): void
    {
        $start = ftell($handle);
        $total = strlen($data);
        $written = 0;

        while ($written < $total) {
            $result = fwrite($handle, substr($data, $written));

            if ($result === false || $result === 0) {
                if (is_int($start) && $start >= 0) {
                    // Discard the partial line rather than leave it for the
                    // next append to concatenate onto.
                    ftruncate($handle, $start);
                }

                return;
            }

            $written += $result;
        }
    }

    public function currentFile(): string
    {
        return sprintf('%s/%s-%s.ndjson', rtrim($this->directory, '/'), $this->prefix, gmdate('Y-m-d'));
    }
}
