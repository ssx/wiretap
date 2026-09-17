<?php

declare(strict_types=1);

namespace Ssx\Wiretap\Query;

/**
 * Filter criteria for reading exchanges back out.
 *
 * Deliberately a value object rather than a fluent builder over a connection:
 * the same query has to be answerable by a file reader, a database, and a
 * test double, none of which share a query language.
 */
final readonly class ExchangeQuery
{
    /**
     * @param string|null $host          Exact host match, compared case-insensitively
     * @param string|null $method        HTTP method
     * @param int|null    $status        Exact status
     * @param string|null $statusClass   '2xx', '4xx', '5xx'
     * @param bool        $failedOnly    Transport errors and 4xx/5xx responses
     * @param float|null  $since         Unix timestamp, inclusive
     * @param float|null  $until         Unix timestamp, exclusive
     */
    public function __construct(
        public ?string $host = null,
        public ?string $method = null,
        public ?int $status = null,
        public ?string $statusClass = null,
        public bool $failedOnly = false,
        public ?string $correlationId = null,
        public ?float $since = null,
        public ?float $until = null,
        public int $limit = 20,
        public int $offset = 0,
        public bool $newestFirst = true,
    ) {
    }

    public function matchesStatus(?int $status): bool
    {
        if ($this->status !== null && $status !== $this->status) {
            return false;
        }

        if ($this->statusClass !== null) {
            if ($status === null) {
                return false;
            }

            $class = (int) substr($this->statusClass, 0, 1);

            if (intdiv($status, 100) !== $class) {
                return false;
            }
        }

        return true;
    }
}
