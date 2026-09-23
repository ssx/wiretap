<?php

declare(strict_types=1);

namespace Ssx\Wiretap\Support;

/**
 * Re-encoding a JSON document without changing what it says.
 *
 * PHP's decode/encode round trip is lossy in three ways that matter to a
 * recorder: an integer beyond PHP_INT_MAX becomes a float and is written back
 * as 1.2345678901234567e+19, `{}` decoded as an array is written back as `[]`,
 * and `10.0` is written back as `10`. Snowflake and Stripe-style ids, empty
 * objects and zero fractions were quietly rewritten in a tool whose whole
 * claim is that it records what actually happened.
 *
 * decode() keeps objects as objects. encode() takes the document the value was
 * decoded from, so oversized integers can be written back as the literals
 * they were.
 */
final class Json
{
    /**
     * Sentinel wrapped around an integer too large for PHP's int type, so it
     * survives the round trip through json_encode as a number.
     */
    private const WIDE_INT = "\x00wiretap:int\x00";

    /**
     * Decode a JSON object or array, keeping `{}` as an object.
     *
     * Null for anything else: malformed input, a truncated prefix, or a
     * document whose top level is a scalar.
     *
     * @return array<array-key, mixed>|\stdClass|null
     */
    public static function decode(string $bytes): array|\stdClass|null
    {
        $decoded = json_decode($bytes);

        return is_array($decoded) || $decoded instanceof \stdClass ? $decoded : null;
    }

    /**
     * Encode a structure decoded from $source, preserving oversized integer
     * literals and zero fractions. False when it cannot be encoded.
     */
    public static function encode(mixed $decoded, string $source, int $flags = 0): string|false
    {
        // A second decode that keeps oversized integer literals as strings.
        // Walked in lockstep with the first, it is what lets an id beyond
        // PHP_INT_MAX be told apart from a JSON string that merely looks like
        // one, so it can be written back out as the integer it was.
        $wide = json_decode($source, false, 512, JSON_BIGINT_AS_STRING);

        $encoded = json_encode(self::markWideIntegers($decoded, $wide), $flags | JSON_PRESERVE_ZERO_FRACTION);

        if ($encoded === false) {
            return false;
        }

        return self::unmarkWideIntegers($encoded);
    }

    /**
     * Replace every oversized integer with a marked string.
     *
     * $plain decoded them as floats; $wide decoded the same document with
     * JSON_BIGINT_AS_STRING. Where the two disagree in exactly that way, the
     * source held an integer literal PHP cannot represent.
     */
    private static function markWideIntegers(mixed $plain, mixed $wide, int $depth = 0): mixed
    {
        if ($depth > 512) {
            return $plain;
        }

        if (is_float($plain) && is_string($wide) && preg_match('/^-?\d+$/', $wide) === 1) {
            return self::WIDE_INT . $wide;
        }

        if (is_array($plain) && is_array($wide)) {
            foreach ($plain as $key => $item) {
                if (array_key_exists($key, $wide)) {
                    $plain[$key] = self::markWideIntegers($item, $wide[$key], $depth + 1);
                }
            }

            return $plain;
        }

        if ($plain instanceof \stdClass && $wide instanceof \stdClass) {
            $other = get_object_vars($wide);

            foreach (get_object_vars($plain) as $key => $item) {
                if (array_key_exists($key, $other)) {
                    $plain->{$key} = self::markWideIntegers($item, $other[$key], $depth + 1);
                }
            }

            return $plain;
        }

        return $plain;
    }

    /**
     * Unquote the marked integers json_encode has just written as strings.
     *
     * The sentinel contains NUL bytes, which json_encode always escapes as
     * \u0000, so the pattern below cannot collide with any content that was
     * genuinely in the document.
     */
    private static function unmarkWideIntegers(string $encoded): string
    {
        if (!str_contains($encoded, '\u0000wiretap:int\u0000')) {
            return $encoded;
        }

        return Regex::replaceCallback(
            '/"\\\\u0000wiretap:int\\\\u0000(-?\d+)"/',
            static fn (array $m): string => $m[1],
            $encoded,
        );
    }
}
