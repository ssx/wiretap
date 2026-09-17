<?php

declare(strict_types=1);

namespace Ssx\Wiretap;

use Ssx\Wiretap\Blocklist\Blocklist;
use Ssx\Wiretap\Contract\ContextEnricher;
use Ssx\Wiretap\Contract\ExchangeSink;
use Ssx\Wiretap\Redaction\Redactor;
use Ssx\Wiretap\Sink\NullSink;

/**
 * The pipeline every captured exchange passes through.
 *
 *   blocklist -> enrichers -> sampler -> redactor -> buffer -> sink
 *
 * The sampler sits before the redactor because every input it reads is final
 * by then, and redaction is the expensive stage: running it on exchanges that
 * are about to be discarded is pure waste, and it hands the host rule a URI
 * that has already been rewritten.
 *
 * Buffering exists because writing to a store inline on a customer-facing
 * request is not acceptable. The buffer is bounded in both count and bytes: a
 * queue consumer never reaches shutdown, so an unbounded buffer there is an
 * out-of-memory error waiting to happen. On overflow we drop and count.
 */
final class Recorder
{
    /** @var list<Exchange> */
    private array $buffer = [];

    private int $bufferedBytes = 0;

    private int $dropped = 0;

    private bool $capturing = false;

    private bool $shutdownRegistered = false;

    /** @var list<ContextEnricher> */
    private array $enrichers = [];

    public function __construct(
        private ExchangeSink $sink = new NullSink(),
        private readonly Blocklist $blocklist = new Blocklist(),
        private readonly Redactor $redactor = new Redactor(),
        private readonly Sampler $sampler = new Sampler(),
        private readonly int $maxBufferedRecords = 200,
        private readonly int $maxBufferedBytes = 8_388_608,
        private bool $enabled = true,
    ) {
    }

    /**
     * Whether this URL will be captured at all.
     *
     * Capture layers must call this *before* reading any body. That ordering
     * is the entire point of the blocklist: a blocked payload should never
     * exist in process memory, not merely never be stored.
     */
    public function shouldCapture(string $url): bool
    {
        if (!$this->enabled || $this->capturing) {
            return false;
        }

        return !$this->blocklist->blocks($url);
    }

    public function record(Exchange $exchange): void
    {
        if (!$this->enabled) {
            return;
        }

        // A sink that ships records over HTTP would be captured by our own
        // hooks and recurse until the process dies. Every entry point is
        // guarded; this is the one that matters.
        if ($this->capturing) {
            return;
        }

        $this->capturing = true;

        try {
            // Re-check: a redirect may have moved the request onto a blocked
            // host after the initial decision was taken.
            if ($this->blocklist->blocks($exchange->uri)) {
                return;
            }

            foreach ($this->enrichers as $enricher) {
                $exchange = $enricher->enrich($exchange);
            }

            // Sample before redacting, not after.
            //
            // Every input the sampler reads — correlation id, failure state,
            // timings, host — is already final at this point, so the decision
            // is the same either way. Doing it second meant that at 1%
            // sampling, 99% of exchanges paid for several JSON decode/encode
            // passes and every configured regex over a body up to 64 KiB
            // before being thrown away. It also handed the host rule a URI
            // that redaction had already rewritten, so a host the operator
            // named in alwaysHosts could stop matching itself.
            if (!$this->sampler->shouldKeep($exchange)) {
                return;
            }

            $exchange = $this->redactor->redact($exchange);

            $this->buffer($exchange);
        } catch (\Throwable) {
            // Instrumentation failures must never change application
            // behaviour, including its exceptions.
        } finally {
            $this->capturing = false;
        }
    }

    private function buffer(Exchange $exchange): void
    {
        $size = $this->serialisedSize($exchange);

        if (count($this->buffer) >= $this->maxBufferedRecords
            || $this->bufferedBytes + $size > $this->maxBufferedBytes) {
            // Flush rather than drop where we can; a long-running worker never
            // reaches shutdown, so thresholds are the only flush it will get.
            $this->flush();
        }

        if ($this->bufferedBytes + $size > $this->maxBufferedBytes) {
            ++$this->dropped;

            return;
        }

        $this->buffer[] = $exchange;
        $this->bufferedBytes += $size;

        $this->registerShutdownFlush();
    }

    /**
     * The record's size in bytes, as the sink will write it.
     *
     * json_encode() returns false on invalid UTF-8, and casting that to a
     * string yields size zero — so a body the encoder choked on counted for
     * nothing against the buffer's byte limit. A 1,001-byte record was
     * retained with an 8 MiB cap set to 100. The sink writes with
     * JSON_INVALID_UTF8_SUBSTITUTE, so the estimate uses the same flags.
     */
    private function serialisedSize(Exchange $exchange): int
    {
        $encoded = json_encode(
            $exchange,
            JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_INVALID_UTF8_SUBSTITUTE,
        );

        if (is_string($encoded)) {
            return strlen($encoded);
        }

        // Still unencodable. Charge it the whole remaining budget rather than
        // nothing, so it cannot slip past the cap.
        return $this->maxBufferedBytes;
    }

    public function flush(): void
    {
        if ($this->buffer === []) {
            return;
        }

        $batch = $this->buffer;
        $this->buffer = [];
        $this->bufferedBytes = 0;

        $wasCapturing = $this->capturing;
        $this->capturing = true;

        try {
            $this->sink->writeBatch($batch);
        } catch (\Throwable) {
        } finally {
            $this->capturing = $wasCapturing;
        }
    }

    /**
     * Flush after the response has gone to the client where the SAPI allows
     * it.
     *
     * This is deferred work, not asynchronous I/O, and it is worth being
     * explicit that it does not run on OOM, a segfault, or a hard
     * max_execution_time kill — which is exactly the hung outbound call
     * someone is most likely to be debugging.
     */
    private function registerShutdownFlush(): void
    {
        if ($this->shutdownRegistered) {
            return;
        }

        $this->shutdownRegistered = true;

        // A weak reference, so a recorder that has been replaced — by
        // Wiretap::fake(), or by a framework booting a second application —
        // can be collected. Capturing $this strongly kept every retired
        // recorder and its in-memory captures alive until the process exited,
        // which in a test suite calling fake() per test is an accumulating
        // leak.
        $weak = \WeakReference::create($this);

        register_shutdown_function(static function () use ($weak): void {
            $weak->get()?->flush();
        });
    }

    public function addEnricher(ContextEnricher $enricher): self
    {
        $this->enrichers[] = $enricher;

        return $this;
    }

    public function setSink(ExchangeSink $sink): self
    {
        $this->sink = $sink;

        return $this;
    }

    public function sink(): ExchangeSink
    {
        return $this->sink;
    }

    public function blocklist(): Blocklist
    {
        return $this->blocklist;
    }

    public function redactor(): Redactor
    {
        return $this->redactor;
    }

    public function enable(): self
    {
        $this->enabled = true;

        return $this;
    }

    public function disable(): self
    {
        $this->enabled = false;

        return $this;
    }

    public function isEnabled(): bool
    {
        return $this->enabled;
    }

    public function dropped(): int
    {
        return $this->dropped;
    }

    /**
     * @return list<Exchange>
     */
    public function buffered(): array
    {
        return $this->buffer;
    }
}
