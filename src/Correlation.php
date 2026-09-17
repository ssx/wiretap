<?php

declare(strict_types=1);

namespace Ssx\Wiretap;

use Ssx\Wiretap\Support\Ulid;

/**
 * Ties every outbound call made while handling one inbound request together.
 *
 * A static holder is pragmatically necessary: the curl capture layer sits
 * below any container and cannot be injected into. The state it holds is
 * plain data and is resettable, which keeps it testable and lets a queue
 * worker clear it between jobs.
 */
final class Correlation
{
    private static ?string $id = null;

    private static int $sequence = 0;

    private static bool $explicit = false;

    /**
     * Adopt an inbound identifier, or generate one.
     *
     * Accepts a W3C traceparent and extracts its trace id, so that outbound
     * calls join up with whatever produced the inbound request.
     */
    public static function start(?string $inbound = null): string
    {
        self::$sequence = 0;
        self::$explicit = true;

        return self::$id = self::normalise($inbound) ?? Ulid::generate();
    }

    public static function id(): string
    {
        return self::$id ??= Ulid::generate();
    }

    /**
     * Whether a correlation is already in scope.
     *
     * Deliberately not id(), which generates one as a side effect. A caller
     * asking "is something already in scope" must be able to find out without
     * creating the answer — a queue listener needs to know whether it is
     * inside an enclosing HTTP request before deciding to start its own.
     */
    public static function hasStarted(): bool
    {
        return self::$id !== null;
    }

    /**
     * Whether something deliberately started this correlation, as opposed to
     * one being generated on demand by the first call to id().
     *
     * The difference decides ownership. A queue listener asking only
     * hasStarted() could not tell "an HTTP request owns this scope" from "the
     * capture middleware called id() on the first outbound call" — so in a
     * worker, one HTTP call at boot meant no job ever got its own correlation
     * again.
     */
    public static function startedExplicitly(): bool
    {
        return self::$explicit;
    }

    /**
     * Monotonic position of this call within the current correlation.
     */
    public static function nextSequence(): int
    {
        return self::$sequence++;
    }

    /**
     * Clear between jobs in a long-running worker, where one process handles
     * many logically separate units of work.
     */
    public static function reset(): void
    {
        self::$id = null;
        self::$sequence = 0;
        self::$explicit = false;
    }

    private static function normalise(?string $inbound): ?string
    {
        if ($inbound === null || trim($inbound) === '') {
            return null;
        }

        $inbound = trim($inbound);

        // W3C traceparent: version-traceid-spanid-flags
        if (preg_match('/^[0-9a-f]{2}-([0-9a-f]{32})-[0-9a-f]{16}-[0-9a-f]{2}$/i', $inbound, $m) === 1) {
            return strtolower($m[1]);
        }

        // Anything else is taken as an opaque request id, bounded in length
        // and stripped of characters that would complicate storage.
        $clean = preg_replace('/[^A-Za-z0-9._:-]/', '', $inbound) ?? '';

        return $clean === '' ? null : substr($clean, 0, 128);
    }
}
