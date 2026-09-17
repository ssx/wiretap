<?php

declare(strict_types=1);

namespace Ssx\Wiretap\Support;

/**
 * Regex validation that does not emit a warning on a bad pattern.
 *
 * The `@` operator is not sufficient here: PHPUnit and several frameworks
 * install error handlers that fire regardless of suppression, so a blocklist
 * or redaction rule with a typo would raise an error from deep inside the
 * instrumentation. Since a capture layer must never disturb the application
 * it observes, validation is done under a handler we control.
 */
final class Regex
{
    public static function isValid(string $pattern): bool
    {
        $valid = true;

        set_error_handler(static function () use (&$valid): bool {
            $valid = false;

            return true;
        });

        try {
            $result = preg_match($pattern, '');
        } catch (\Throwable) {
            return false;
        } finally {
            restore_error_handler();
        }

        return $valid && $result !== false;
    }

    /**
     * Replace, reporting whether the pattern actually ran.
     *
     * preg_replace_callback returns null on an execution failure — invalid
     * UTF-8 in the subject, or a backtrack limit. Falling back to the original
     * subject restored the very secret the pattern existed to remove, and the
     * caller had no way to know. $ran lets the caller fail closed instead.
     *
     * @param callable(array<int|string, string>): string $callback
     */
    public static function replaceCallback(string $pattern, callable $callback, string $subject, ?bool &$ran = null): string
    {
        if (!self::isValid($pattern)) {
            $ran = false;

            return $subject;
        }

        $result = preg_replace_callback($pattern, $callback, $subject);

        if ($result === null) {
            $ran = false;

            return $subject;
        }

        $ran = true;

        return $result;
    }
}
