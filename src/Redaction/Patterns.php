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
