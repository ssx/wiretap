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

        foreach ($this->query(new ExchangeQuery(
            host: $query->host,
            method: $query->method,
            status: $query->status,
            statusClass: $query->statusClass,
            failedOnly: $query->failedOnly,
            correlationId: $query->correlationId,
            limit: max($position, 1),
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
            $lines = $this->fileLines($file);

            if ($newestFirst) {
                $lines = array_reverse($lines);
            }

            yield from $lines;
        }
    }

    /**
     * @return list<string>
     */
    private function fileLines(string $file): array
    {
        $handle = @fopen($file, 'rb');

        if ($handle === false) {
            return [];
        }

        $lines = [];

        try {
            while (($line = fgets($handle)) !== false) {
                $line = trim($line);

                if ($line !== '') {
                    $lines[] = $line;
                }
            }
        } finally {
            fclose($handle);
        }

        return $lines;
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
