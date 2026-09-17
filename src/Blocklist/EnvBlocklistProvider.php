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

        return self::tokenise($raw);
    }

    public function name(): string
    {
        return 'env:' . $this->variable;
    }

    /**
     * Split on commas and newlines, but never inside a tilde-delimited regex.
     *
     * `~^https://example[.]com/pay/[0-9]{1,3}$~` contains a comma in its
     * quantifier. Splitting naively produced two broken rules, and the traffic
     * the rule existed to block was captured — with only a compile error in a
     * diagnostics command to show for it.
     *
     * @return list<string>
     */
    private static function tokenise(string $raw): array
    {
        $patterns = [];
        $current = '';
        $inRegex = false;
        $length = strlen($raw);

        for ($i = 0; $i < $length; ++$i) {
            $char = $raw[$i];

            if ($char === '~') {
                // A tilde opens a regex only at the start of a token.
                if (!$inRegex && trim($current) === '') {
                    $inRegex = true;
                } elseif ($inRegex) {
                    $inRegex = false;
                }

                $current .= $char;

                continue;
            }

            if (!$inRegex && ($char === ',' || $char === "\n" || $char === "\r")) {
                $patterns[] = $current;
                $current = '';

                continue;
            }

            $current .= $char;
        }

        $patterns[] = $current;

        return array_values(array_filter(
            array_map('trim', $patterns),
            static fn (string $p): bool => $p !== '',
        ));
    }
}
