<?php

declare(strict_types=1);

namespace Ssx\Wiretap\Redaction;

/**
 * Built-in secret detectors.
 *
 * These are the last line before the safety net, not the first line of
 * defence. Structured rules — header names, query parameters, body paths —
 * are precise; regexes are a net for what those rules missed.
 */
final class Patterns
{
    /**
     * Candidate card numbers: 13 to 19 digits, optionally separated by single
     * spaces or hyphens, not preceded or followed by another digit.
     *
     * This matches far more than it should on its own, which is why every hit
     * is Luhn-checked before being redacted. A bare \d{13,19} fires on order
     * IDs, SKUs and millisecond timestamps, and a rule with that false
     * positive rate is one people switch off.
     */
    public const PAN = '/(?<![0-9])(?:[0-9][ -]?){12,18}[0-9](?![0-9])/';

    public const BEARER = '/\bBearer\s+[A-Za-z0-9\-._~+\/]+=*/i';

    public const JWT = '/\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*/';

    public const AWS_KEY = '/\b(?:AKIA|ASIA|AROA|AIDA)[0-9A-Z]{16}\b/';

    public const STRIPE_KEY = '/\b(?:sk|rk|pk)_(?:live|test)_[0-9a-zA-Z]{10,}/';

    public const EMAIL = '/\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b/';

    /**
     * @return array<string, string>
     */
    public static function all(): array
    {
        return [
            'pan' => self::PAN,
            'bearer' => self::BEARER,
            'jwt' => self::JWT,
            'aws_key' => self::AWS_KEY,
            'stripe_key' => self::STRIPE_KEY,
            'email' => self::EMAIL,
        ];
    }

    /**
     * The Luhn check digit algorithm.
     *
     * Applied to every PAN candidate. This is the difference between a usable
     * rule and one that is disabled within a day.
     */
    /**
     * Find the valid card numbers inside a run of digits and separators.
     *
     * The greedy PAN regex matches the longest run it can, so
     * `4111111111111111 123` matches as one 19-digit candidate whose Luhn
     * check fails, and the valid card inside it is never reconsidered.
     * Adjacent numeric fields are ordinary in a JSON payload.
     *
     * Candidates are built from whole separator-delimited groups rather than
     * arbitrary substrings. That distinction matters: scanning every substring
     * finds a 14-digit Luhn-valid sequence inside the perfectly ordinary order
     * reference 1234567890123456, and redacting order references is how a
     * redaction rule gets switched off. A real card number is written as whole
     * groups — `4111 1111 1111 1111` — so whole groups are what we consider.
     *
     * @return list<string>
     */
    public static function findPans(string $candidate): array
    {
        if (self::passesLuhn($candidate)) {
            return [$candidate];
        }

        // Keep each group's offset, so the value returned is an exact
        // substring of the input. Rebuilding it with a chosen separator would
        // produce text that str_replace cannot find when the original used a
        // different one.
        if (preg_match_all('/[0-9]+/', $candidate, $matches, PREG_OFFSET_CAPTURE) === false) {
            return [];
        }

        /** @var list<array{0: string, 1: int}> $groups */
        $groups = $matches[0];
        $count = count($groups);

        if ($count < 2) {
            // A single unbroken run that already failed Luhn. Splitting it
            // further would be inventing a card number that was never written.
            return [];
        }

        // Longest spans first, so the fullest card wins over a shorter valid
        // sequence inside it.
        for ($length = $count; $length >= 1; --$length) {
            for ($offset = 0; $offset + $length <= $count; ++$offset) {
                $slice = array_slice($groups, $offset, $length);
                $first = $slice[0];
                $last = $slice[$length - 1];

                $startPos = $first[1];
                $endPos = $last[1] + strlen($last[0]);
                $text = substr($candidate, $startPos, $endPos - $startPos);

                // Only separators may sit between the groups, or this is not
                // one number written with separators.
                if (preg_match('/^[0-9]+(?:[ -][0-9]+)*$/', $text) !== 1) {
                    continue;
                }

                if (self::passesLuhn($text)) {
                    return [$text];
                }
            }
        }

        return [];
    }

    public static function passesLuhn(string $candidate): bool
    {
        $digits = preg_replace('/[^0-9]/', '', $candidate) ?? '';
        $length = strlen($digits);

        if ($length < 13 || $length > 19) {
            return false;
        }

        $sum = 0;
        $double = false;

        for ($i = $length - 1; $i >= 0; --$i) {
            $digit = (int) $digits[$i];

            if ($double) {
                $digit *= 2;

                if ($digit > 9) {
                    $digit -= 9;
                }
            }

            $sum += $digit;
            $double = !$double;
        }

        return $sum % 10 === 0;
    }
}
