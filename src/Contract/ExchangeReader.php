<?php

declare(strict_types=1);

namespace Ssx\Wiretap\Contract;

use Ssx\Wiretap\Exchange;
use Ssx\Wiretap\Query\ExchangeQuery;

/**
 * A store that can be searched. Implemented by the file and database sinks;
 * not by PSR-3, which has no read side.
 */
interface ExchangeReader
{
    /**
     * @return iterable<Exchange>
     */
    public function query(ExchangeQuery $query): iterable;

    public function find(string $id): ?Exchange;
}
