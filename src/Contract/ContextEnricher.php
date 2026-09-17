<?php

declare(strict_types=1);

namespace Ssx\Wiretap\Contract;

use Ssx\Wiretap\Exchange;

/**
 * Adds application context to an exchange — the route, the console command,
 * the store id, the job name. The capture layers sit below the framework and
 * cannot know any of that, so integrations supply it.
 */
interface ContextEnricher
{
    public function enrich(Exchange $exchange): Exchange;
}
