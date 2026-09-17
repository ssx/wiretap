<?php

declare(strict_types=1);

namespace Ssx\Wiretap\Blocklist;

use Ssx\Wiretap\Contract\BlocklistProvider;

/**
 * Union of several providers. Never an intersection — see Blocklist.
 */
final readonly class ChainBlocklistProvider implements BlocklistProvider
{
    /** @var list<BlocklistProvider> */
    private array $providers;

    public function __construct(BlocklistProvider ...$providers)
    {
        $this->providers = array_values($providers);
    }

    public function patterns(): iterable
    {
        foreach ($this->providers as $provider) {
            yield from $provider->patterns();
        }
    }

    public function name(): string
    {
        return 'chain(' . implode(', ', array_map(
            static fn (BlocklistProvider $p): string => $p->name(),
            $this->providers,
        )) . ')';
    }
}
