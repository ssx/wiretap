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

        return self::parse($raw);
    }

    /**
     * Split a raw blocklist string into patterns.
     *
     * Public because framework integrations have to apply exactly these rules
     * before their configuration is cached — Laravel's config:cache stops
     * loading .env, so a bridge that parses the variable differently produces
     * a different blocklist in production than in development.
     *
     * @return list<string>
     */
    public static function parse(string $raw): array
    {
        return self::tokenise($raw);
    }

    public function name(): string
    {
        return 'env:' . $this->variable;
    }

    /**
     * Whether the character about to be read is escaped.
     *
     * An odd number of trailing backslashes escapes it; an even number is a
     * run of literal backslashes and does not.
     */
    private static function isEscaped(string $soFar): bool
    {
        $backslashes = 0;

        for ($i = strlen($soFar) - 1; $i >= 0 && $soFar[$i] === '\\'; --$i) {
            ++$backslashes;
        }

        return $backslashes % 2 === 1;
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

            if ($char === '~' && !self::isEscaped($current)) {
                // A tilde opens a regex only at the start of a token, and an
                // escaped one closes nothing: `~...\~user...~` is a single
                // valid rule, and treating the middle tilde as the delimiter
                // split it at the next comma and discarded it as invalid.
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

        if ($inRegex) {
            // The regex was never closed — a typo. Everything after its
            // opening tilde was swallowed into one token, so a mistake in the
            // first rule silently discarded every rule after it and left
            // nothing blocked and nothing reported.
            //
            // Re-split the unterminated remainder plainly. The broken regex
            // itself still fails to compile and is reported as an error, which
            // is the outcome someone can act on; the rules after it survive.
            $patterns = array_merge(
                $patterns,
                preg_split('/[,\r\n]+/', $current) ?: [$current],
            );
        } else {
            $patterns[] = $current;
        }

        return array_values(array_filter(
            array_map('trim', $patterns),
            static fn (string $p): bool => $p !== '',
        ));
    }
}
