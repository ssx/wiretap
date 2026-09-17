<?php

declare(strict_types=1);

namespace Ssx\Wiretap\Blocklist;

use Ssx\Wiretap\Contract\BlocklistProvider;

final readonly class ArrayBlocklistProvider implements BlocklistProvider
{
    /**
     * @param list<string> $patterns
     */
    public function __construct(
        private array $patterns,
        private string $name = 'array',
    ) {
    }

    public function patterns(): iterable
    {
        return $this->patterns;
    }

    public function name(): string
    {
        return $this->name;
    }
}
