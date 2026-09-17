<?php

declare(strict_types=1);

namespace Ssx\Wiretap\Support;

/**
 * A query string as an ordered list of pairs.
 *
 * PHP's own parse_str() is built for reading request input, not for recording
 * it, and every one of its conveniences is a defect here:
 *
 * - It keeps only the last value of a repeated key, so `?token=A&token=B`
 *   arrives as a single value. The redactor then never sees A, never learns
 *   it as a secret, and a response echoing A is stored in plaintext.
 * - It truncates silently at `max_input_vars` (1000 by default) and raises an
 *   E_WARNING while doing it. Anything past the limit is invisible to the
 *   redactor, and under a framework error handler the warning becomes an
 *   exception thrown from inside the instrumentation.
 * - It rewrites `.` and space in names to `_`, and folds `a[b]` into nested
 *   arrays, so the query cannot be rebuilt as it was sent.
 *
 * A recorder needs the opposite of all that: every pair, in order, with names
 * intact. Nothing here is lossy, so parse() followed by build() returns an
 * equivalent query string.
 */
final class QueryString
{
    /**
     * Split a query string into decoded name/value pairs.
     *
     * A pair with no `=` keeps a null value, so `?flag` is not silently
     * rewritten as `?flag=`.
     *
     * @return list<array{string, string|null}>
     */
    public static function parse(string $query): array
    {
        if ($query === '') {
            return [];
        }

        $pairs = [];

        foreach (explode('&', $query) as $part) {
            if ($part === '') {
                continue;
            }

            $split = strpos($part, '=');

            if ($split === false) {
                $pairs[] = [urldecode($part), null];

                continue;
            }

            $pairs[] = [
                urldecode(substr($part, 0, $split)),
                urldecode(substr($part, $split + 1)),
            ];
        }

        return $pairs;
    }

    /**
     * Rebuild a query string from pairs, preserving order and duplicates.
     *
     * @param list<array{string, string|null}> $pairs
     */
    public static function build(array $pairs): string
    {
        $parts = [];

        foreach ($pairs as [$name, $value]) {
            $parts[] = $value === null
                ? rawurlencode($name)
                : rawurlencode($name) . '=' . rawurlencode($value);
        }

        return implode('&', $parts);
    }

    /**
     * The name without any array subscript: `token[0]` and `token[]` are both
     * `token`, so a rule naming `token` covers them.
     */
    public static function baseName(string $name): string
    {
        $bracket = strpos($name, '[');

        return $bracket === false ? $name : substr($name, 0, $bracket);
    }
}
