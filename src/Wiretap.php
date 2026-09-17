<?php

declare(strict_types=1);

namespace Ssx\Wiretap;

use Ssx\Wiretap\Blocklist\Blocklist;
use Ssx\Wiretap\Blocklist\EnvBlocklistProvider;
use Ssx\Wiretap\Blocklist\PresetBlocklistProvider;
use Ssx\Wiretap\Contract\ExchangeSink;
use Ssx\Wiretap\Redaction\RedactionConfig;
use Ssx\Wiretap\Redaction\Redactor;
use Ssx\Wiretap\Sink\InMemorySink;
use Ssx\Wiretap\Sink\NdjsonFileSink;
use Ssx\Wiretap\Sink\NullSink;
use Ssx\Wiretap\Testing\AssertionFailed;
use Ssx\Wiretap\Testing\RecordedCalls;

/**
 * The global entry point, and the test API.
 *
 * A static holder is pragmatically necessary: the capture layers sit below any
 * container — the curl hooks in particular run in code that cannot be injected
 * into — so there has to be one place they can all reach. Everything it holds
 * is replaceable and resettable, which keeps it testable.
 *
 * This is the single holder. Capture packages resolve from here rather than
 * keeping their own, so a framework wiring up a properly configured recorder
 * changes what every layer writes to.
 */
final class Wiretap
{
    private static ?Recorder $recorder = null;

    private static ?InMemorySink $fakeSink = null;

    public static function recorder(): Recorder
    {
        return self::$recorder ??= self::defaultRecorder();
    }

    public static function setRecorder(Recorder $recorder): Recorder
    {
        self::$fakeSink = null;

        return self::$recorder = $recorder;
    }

    public static function isFaked(): bool
    {
        return self::$fakeSink !== null;
    }

    public static function reset(): void
    {
        self::$recorder = null;
        self::$fakeSink = null;
        Correlation::reset();
    }

    // ---------------------------------------------------------------------
    // Test API
    // ---------------------------------------------------------------------

    /**
     * Capture everything in memory for the duration of a test.
     *
     * Call it in a setUp or a beforeEach. Nothing reaches disk, sampling is
     * off so every call is kept, and the blocklist is empty by default —
     * a test asserting on a payment call should not have that call silently
     * dropped by a preset.
     */
    public static function fake(?Blocklist $blocklist = null): InMemorySink
    {
        self::$fakeSink = new InMemorySink(limit: 10_000);

        self::$recorder = new Recorder(
            sink: self::$fakeSink,
            blocklist: $blocklist ?? new Blocklist(),
            redactor: new Redactor(new RedactionConfig(enabled: false)),
            sampler: new Sampler(),
        );

        return self::$fakeSink;
    }

    /**
     * Everything recorded since fake() was called.
     */
    public static function recorded(): RecordedCalls
    {
        if (self::$fakeSink === null) {
            throw new AssertionFailed(
                'Wiretap::fake() must be called before assertions. Add it to your test setUp or beforeEach.'
            );
        }

        self::recorder()->flush();

        return new RecordedCalls(self::$fakeSink->all());
    }

    /**
     * Capture the calls made inside one closure, regardless of global config.
     *
     * The point of scoping it: it works in a running application where
     * capture is otherwise disabled or sampled, without changing anything for
     * the rest of the process.
     *
     * @template T
     *
     * @param callable(): T $callback
     */
    public static function debug(callable $callback, ?RecordedCalls &$calls = null): mixed
    {
        $previousRecorder = self::$recorder;
        $previousFake = self::$fakeSink;

        $sink = self::fake();

        try {
            return $callback();
        } finally {
            self::recorder()->flush();
            $calls = new RecordedCalls($sink->all());

            self::$recorder = $previousRecorder;
            self::$fakeSink = $previousFake;
        }
    }

    // ---------------------------------------------------------------------
    // Assertions
    // ---------------------------------------------------------------------

    /**
     * @param callable(Exchange): bool|string $matcher A callback, or a host
     */
    public static function assertSent(callable|string $matcher, ?int $times = null): void
    {
        $matched = self::match($matcher);
        $description = is_string($matcher) ? "to host [{$matcher}]" : 'matching the given callback';

        if ($times !== null) {
            self::assert(
                $matched->count() === $times,
                sprintf(
                    'Expected %d request(s) %s, but %d were sent.%s',
                    $times,
                    $description,
                    $matched->count(),
                    self::context(),
                ),
            );

            return;
        }

        self::assert(
            !$matched->isEmpty(),
            sprintf('Expected a request %s, but none was sent.%s', $description, self::context()),
        );
    }

    /**
     * @param callable(Exchange): bool|string $matcher
     */
    public static function assertNotSent(callable|string $matcher): void
    {
        $matched = self::match($matcher);
        $description = is_string($matcher) ? "to host [{$matcher}]" : 'matching the given callback';

        self::assert(
            $matched->isEmpty(),
            sprintf(
                'Expected no request %s, but %d were sent.%s',
                $description,
                $matched->count(),
                self::context(),
            ),
        );
    }

    public static function assertNothingSent(): void
    {
        $recorded = self::recorded();

        self::assert(
            $recorded->isEmpty(),
            sprintf('Expected no outbound requests, but %d were sent.%s', $recorded->count(), self::context()),
        );
    }

    public static function assertNothingSentTo(string $host): void
    {
        self::assertNotSent($host);
    }

    public static function assertSentCount(int $expected): void
    {
        $recorded = self::recorded();

        self::assert(
            $recorded->count() === $expected,
            sprintf(
                'Expected %d outbound request(s), but %d were sent.%s',
                $expected,
                $recorded->count(),
                self::context(),
            ),
        );
    }

    /**
     * @param callable(Exchange): bool|string $matcher
     */
    private static function match(callable|string $matcher): RecordedCalls
    {
        $recorded = self::recorded();

        return is_string($matcher)
            ? $recorded->toHost($matcher)
            : $recorded->filter($matcher);
    }

    /**
     * Route through PHPUnit where it is available, so a failure counts as a
     * failed assertion rather than an errored test. Fall back to an exception
     * everywhere else.
     */
    private static function assert(bool $condition, string $message): void
    {
        if (class_exists(\PHPUnit\Framework\Assert::class)) {
            \PHPUnit\Framework\Assert::assertTrue($condition, $message);

            return;
        }

        if (!$condition) {
            throw new AssertionFailed($message);
        }
    }

    /**
     * Every failure message lists what actually happened. Without it the
     * first thing anyone does is add a dump() and run again.
     */
    private static function context(): string
    {
        $recorded = self::$fakeSink === null
            ? new RecordedCalls()
            : new RecordedCalls(self::$fakeSink->all());

        return PHP_EOL . PHP_EOL . 'Recorded:' . PHP_EOL . $recorded->describe() . PHP_EOL;
    }

    // ---------------------------------------------------------------------

    /**
     * Defaults for a process that has done nothing but install the package.
     *
     * Capture is off unless WIRETAP_ENABLED is truthy. A package that began
     * recording personal data the moment it was installed would be
     * indefensible.
     */
    private static function defaultRecorder(): Recorder
    {
        $enabled = filter_var(getenv('WIRETAP_ENABLED') ?: 'false', FILTER_VALIDATE_BOOL);

        return new Recorder(
            sink: $enabled ? self::defaultSink() : new NullSink(),
            blocklist: new Blocklist([
                new PresetBlocklistProvider([
                    PresetBlocklistProvider::PAYMENT_GATEWAYS,
                    PresetBlocklistProvider::CLOUD_METADATA,
                ]),
                new EnvBlocklistProvider(),
            ]),
            redactor: new Redactor(new RedactionConfig(
                maxBodyBytes: self::intFromEnv('WIRETAP_BODY_LIMIT', 65536),
            )),
            sampler: new Sampler(
                rateBasisPoints: self::intFromEnv('WIRETAP_SAMPLE_BP', 10000),
            ),
            enabled: $enabled,
        );
    }

    /**
     * Read an integer from the environment.
     *
     * `?:` cannot be used here: PHP treats the string "0" as falsy, so
     * WIRETAP_SAMPLE_BP=0 — meaning "sample nothing" — silently became the
     * 10000 default and kept everything. The same applied to a zero body
     * limit.
     */
    private static function intFromEnv(string $name, int $default): int
    {
        $value = getenv($name);

        if (!is_string($value) || trim($value) === '' || !is_numeric(trim($value))) {
            return $default;
        }

        return max(0, (int) trim($value));
    }

    private static function defaultSink(): ExchangeSink
    {
        $path = getenv('WIRETAP_PATH');

        if (!is_string($path) || $path === '') {
            $path = sys_get_temp_dir() . '/wiretap';
        }

        return new NdjsonFileSink($path);
    }
}
