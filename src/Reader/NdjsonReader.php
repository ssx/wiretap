<?php

declare(strict_types=1);

namespace Ssx\Wiretap\Reader;

use Ssx\Wiretap\Contract\ExchangeReader;
use Ssx\Wiretap\Exchange;
use Ssx\Wiretap\Query\ExchangeQuery;

/**
 * Reads exchanges back out of the NDJSON files the default sink writes.
 *
 * Files are read newest-first and line-by-line rather than loaded whole: a
 * debugging session can easily produce a log larger than memory, and the
 * common query only wants the last twenty records.
 */
final readonly class NdjsonReader implements ExchangeReader
{
    public function __construct(
        private string $directory,
        private string $prefix = 'wiretap',
    ) {
    }

    public function query(ExchangeQuery $query): iterable
    {
        $matched = 0;
        $skipped = 0;

        foreach ($this->lines($query->newestFirst) as $line) {
            $exchange = $this->decode($line);

            if ($exchange === null || !$this->matches($exchange, $query)) {
                continue;
            }

            if ($skipped < $query->offset) {
                ++$skipped;

                continue;
            }

            yield $exchange;

            if (++$matched >= $query->limit) {
                return;
            }
        }
    }

    public function find(string $id): ?Exchange
    {
        foreach ($this->lines(true) as $line) {
            // Cheap pre-filter: decoding every record to find one id is waste.
            if (!str_contains($line, $id)) {
                continue;
            }

            $exchange = $this->decode($line);

            if ($exchange !== null && $exchange->id === $id) {
                return $exchange;
            }
        }

        return null;
    }

    /**
     * Resolve a 1-based position in the default listing, so `wiretap show 1`
     * means "the one at the top of the list I just looked at".
     */
    public function findByPosition(int $position, ExchangeQuery $query): ?Exchange
    {
        $index = 1;

        // Every selection field is carried over. Dropping since/until/offset
        // meant `list --offset=20` followed by `show 1 --offset=20` opened the
        // first overall result rather than the row that was displayed.
        foreach ($this->query(new ExchangeQuery(
            host: $query->host,
            method: $query->method,
            status: $query->status,
            statusClass: $query->statusClass,
            failedOnly: $query->failedOnly,
            correlationId: $query->correlationId,
            since: $query->since,
            until: $query->until,
            limit: max($position, 1),
            offset: $query->offset,
            newestFirst: $query->newestFirst,
        )) as $exchange) {
            if ($index++ === $position) {
                return $exchange;
            }
        }

        return null;
    }

    /**
     * @return list<string>
     */
    public function files(): array
    {
        $pattern = sprintf('%s/%s-*.ndjson', rtrim($this->directory, '/'), $this->prefix);
        $files = glob($pattern) ?: [];

        sort($files);

        return array_values($files);
    }

    /**
     * @return \Generator<int, string>
     */
    private function lines(bool $newestFirst): \Generator
    {
        $files = $this->files();

        if ($newestFirst) {
            $files = array_reverse($files);
        }

        foreach ($files as $file) {
            yield from $newestFirst
                ? $this->linesBackwards($file)
                : $this->linesForwards($file);
        }
    }

    /**
     * @return \Generator<int, string>
     */
    private function linesForwards(string $file): \Generator
    {
        $handle = @fopen($file, 'rb');

        if ($handle === false) {
            return;
        }

        try {
            while (($line = fgets($handle)) !== false) {
                $line = trim($line);

                if ($line !== '') {
                    yield $line;
                }
            }
        } finally {
            fclose($handle);
        }
    }

    /**
     * Read a file backwards, a chunk at a time.
     *
     * The previous implementation built an array of every line in the file and
     * then reversed it. A day's capture can be larger than available memory, so
     * even `wiretap list --limit=1` — which needs exactly one record — could
     * fail on the file it was asked to read from.
     *
     * @return \Generator<int, string>
     */
    private function linesBackwards(string $file, int $chunkSize = 65536): \Generator
    {
        $handle = @fopen($file, 'rb');

        if ($handle === false) {
            return;
        }

        try {
            $position = @filesize($file);

            if (!is_int($position) || $position === 0) {
                return;
            }

            // Anything after the last newline, carried between chunks.
            $remainder = '';

            while ($position > 0) {
                $read = (int) min($chunkSize, $position);

                if ($read < 1) {
                    return;
                }

                $position -= $read;

                if (fseek($handle, $position) !== 0) {
                    return;
                }

                $chunk = fread($handle, $read);

                if ($chunk === false) {
                    return;
                }

                $buffer = $chunk . $remainder;
                $lines = explode("\n", $buffer);

                // The first element may be a partial line continued in the
                // chunk before this one, so it is held back.
                // explode() always yields at least one element, so the shift
                // cannot come back empty here.
                $remainder = (string) array_shift($lines);

                for ($i = count($lines) - 1; $i >= 0; --$i) {
                    $line = trim($lines[$i]);

                    if ($line !== '') {
                        yield $line;
                    }
                }
            }

            $remainder = trim($remainder);

            if ($remainder !== '') {
                yield $remainder;
            }
        } finally {
            fclose($handle);
        }
    }

    private function decode(string $line): ?Exchange
    {
        try {
            $data = json_decode($line, true, 512, JSON_THROW_ON_ERROR);
        } catch (\JsonException) {
            // A line torn by a crash mid-write. Skip it rather than abandon
            // the whole listing.
            return null;
        }

        if (!is_array($data)) {
            return null;
        }

        try {
            return Exchange::fromArray($data);
        } catch (\Throwable) {
            return null;
        }
    }

    private function matches(Exchange $exchange, ExchangeQuery $query): bool
    {
        if ($query->host !== null) {
            $host = $exchange->host();

            if ($host === null || strcasecmp($host, $query->host) !== 0) {
                return false;
            }
        }

        if ($query->method !== null && strcasecmp($exchange->method, $query->method) !== 0) {
            return false;
        }

        if ($query->failedOnly && !$exchange->failed()) {
            return false;
        }

        if ($query->correlationId !== null && $exchange->correlationId !== $query->correlationId) {
            return false;
        }

        if ($query->since !== null && $exchange->startedAt < $query->since) {
            return false;
        }

        if ($query->until !== null && $exchange->startedAt >= $query->until) {
            return false;
        }

        return $query->matchesStatus($exchange->status);
    }
}
