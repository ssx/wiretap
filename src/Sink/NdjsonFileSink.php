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
        // Owner only. A capture file holds Authorization headers, session
        // cookies and request bodies; group-readable is a wider audience than
        // anything in here warrants by default. Callers who genuinely share a
        // log group can widen it explicitly.
        private readonly int $filePermissions = 0o600,
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

    /**
     * Whether the log directory belongs to the user this process runs as.
     *
     * A directory someone else owns is one they can read, and on a shared
     * host that is the whole exposure: captures contain credentials and
     * personal data by design. Refusing to write is the correct outcome —
     * losing a debug record costs nothing next to publishing one.
     */
    private function directoryIsOurs(): bool
    {
        if (!function_exists('posix_geteuid')) {
            return true;
        }

        $owner = @fileowner($this->directory);

        return $owner === false || $owner === posix_geteuid();
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
            if (!is_dir($this->directory)) {
                if (!@mkdir($this->directory, 0o700, true) && !is_dir($this->directory)) {
                    return;
                }

                // mkdir's mode is masked by umask, so set it explicitly.
                @chmod($this->directory, 0o700);
            }

            if (!$this->directoryIsOurs()) {
                return;
            }

            // A directory someone created before us — or left open — keeps
            // whatever mode it had, so captures were being written into a
            // listable, traversable directory. Only bits are removed, never
            // added: the directory keeps no wider an audience than the files.
            $this->tighten($this->directory, $this->directoryMode());

            $path = $this->currentFile();

            // Never follow a symlink here. Appending through one hands an
            // attacker who can create names in this directory an arbitrary
            // file append as this user.
            if (is_link($path)) {
                return;
            }

            $new = !file_exists($path);

            $handle = @fopen($path, 'ab');

            if ($handle === false) {
                return;
            }

            // Tighten permissions before the first record is written, not
            // after. Creation applies the process umask, which is commonly
            // 0022 — so a file created here was world-readable for the whole
            // write, and anything appended in that window stayed readable to
            // every account on the host until the next record arrived.
            //
            // An existing file is tightened too. One created by an earlier
            // version, by hand, or by a process with a different umask stayed
            // world-readable for good, however many records went into it.
            if ($new) {
                @chmod($path, $this->filePermissions);
            } else {
                $this->tighten($path, $this->filePermissions);
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

        } catch (\Throwable) {
            // See MultiSink: never propagate into the application.
        } finally {
            restore_error_handler();
        }
    }

    /**
     * Remove any permission bit that $allowed does not grant.
     *
     * Only for paths this process owns; chmod on anything else fails anyway,
     * and the ownership check above has already refused a foreign directory.
     */
    private function tighten(string $path, int $allowed): void
    {
        $mode = @fileperms($path);

        if ($mode === false) {
            return;
        }

        $mode &= 0o777;

        if (($mode & ~$allowed) !== 0) {
            @chmod($path, $mode & $allowed);
        }
    }

    /**
     * The directory mode that matches the file mode: owner rwx, and read plus
     * traverse for whichever group or other bits the files are readable by.
     */
    private function directoryMode(): int
    {
        $mode = 0o700;

        foreach ([0o040 => 0o050, 0o004 => 0o005] as $read => $grant) {
            if (($this->filePermissions & $read) !== 0) {
                $mode |= $grant;
            }
        }

        return $mode;
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
