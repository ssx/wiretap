<?php

declare(strict_types=1);

namespace Ssx\Wiretap\Support;

/**
 * Minimal ULID generator.
 *
 * Lexicographically sortable by creation time, which means a store can order
 * by id without a secondary index on the timestamp. Implemented here rather
 * than pulled in as a dependency so the core package requires nothing but
 * PHP itself.
 */
final class Ulid
{
    private const ALPHABET = '0123456789ABCDEFGHJKMNPQRSTVWXYZ';

    public static function generate(?float $now = null): string
    {
        $timestamp = (int) round(($now ?? microtime(true)) * 1000);

        $time = '';
        for ($i = 9; $i >= 0; --$i) {
            $time = self::ALPHABET[$timestamp % 32] . $time;
            $timestamp = intdiv($timestamp, 32);
        }

        $random = '';
        for ($i = 0; $i < 16; ++$i) {
            $random .= self::ALPHABET[random_int(0, 31)];
        }

        return $time . $random;
    }
}
