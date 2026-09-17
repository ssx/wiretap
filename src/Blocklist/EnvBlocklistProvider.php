<?php

declare(strict_types=1);

namespace Ssx\Wiretap\Blocklist;

use Ssx\Wiretap\Contract\BlocklistProvider;

/**
 * Reads a comma or newline separated list from an environment variable.
 * Intended for containerised deployments where config files are baked in.
 */
final readonly class EnvBlocklistProvider implements BlocklistProvider
{
    public function __construct(private string $variable = 'WIRETAP_BLOCK')
    {
    }

    public function patterns(): iterable
    {
        $raw = getenv($this->variable);

        if ($raw === false || trim($raw) === '') {
            return [];
        }

        return array_values(array_filter(
            array_map('trim', preg_split('/[,\r\n]+/', $raw) ?: []),
            static fn (string $p): bool => $p !== '',
        ));
    }

    public function name(): string
    {
        return 'env:' . $this->variable;
    }
}
