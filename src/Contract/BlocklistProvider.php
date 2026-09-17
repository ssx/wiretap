<?php

declare(strict_types=1);

namespace Ssx\Wiretap\Contract;

/**
 * Supplies URL patterns whose traffic must never be captured.
 *
 * Where the patterns come from is the integration's problem: a Magento system
 * config textarea, a Laravel config file, an environment variable. The core
 * only defines the contract and the matching rules.
 *
 * Implementations may throw. The chain treats a throwing provider as blocking
 * everything, on the principle that a blocklist which silently empties itself
 * when the database is down is worse than no blocklist at all.
 */
interface BlocklistProvider
{
    /**
     * @return iterable<string>
     */
    public function patterns(): iterable;

    /**
     * A short identifier for diagnostics, e.g. "magento:wiretap/privacy".
     */
    public function name(): string;
}
