<?php

declare(strict_types=1);

namespace Ssx\Wiretap\Blocklist;

use Ssx\Wiretap\Contract\BlocklistProvider;

/**
 * The pre-capture gate.
 *
 * This is not a filter over recorded data. A URL that matches here produces
 * no Exchange at all: no body is read, no headers are copied, nothing reaches
 * a buffer. The distinction matters for cardholder data — redacting a gateway
 * payload means the plaintext existed in process memory and passed through
 * the redactor; blocking the host means it never did.
 *
 * Providers are merged, never intersected. Registering another provider can
 * only ever block more traffic. There is deliberately no mechanism by which
 * one provider unblocks what another blocked, because that would be a
 * privilege escalation on a safety control.
 */
final class Blocklist
{
    /**
     * Distinct hosts counted before the rest are aggregated. Diagnostics only
     * ever show the top few, so a larger number would buy nothing.
     */
    private const MAX_COUNTED_HOSTS = 256;

    /** @var list<BlocklistProvider> */
    private array $providers = [];

    /** @var list<Pattern>|null */
    private ?array $compiled = null;

    /** @var array<string, int> */
    private array $blockCounts = [];

    /** @var list<string> */
    private array $errors = [];

    private bool $failedClosed = false;

    /**
     * Set while the providers are being read.
     */
    private bool $compiling = false;

    /**
     * When the failed-closed compile happened, so it can be retried.
     */
    private ?int $failedAt = null;

    /**
     * @param iterable<BlocklistProvider> $providers
     * @param int $retryFailedAfterSeconds How long a failed-closed state is
     *        held before the providers are asked again; 0 disables the retry
     */
    public function __construct(iterable $providers = [], private readonly int $retryFailedAfterSeconds = 60)
    {
        foreach ($providers as $provider) {
            $this->add($provider);
        }
    }

    /**
     * Discard the compiled rules so the providers are read again.
     *
     * For a long-running worker that wants to pick up a configuration change,
     * and for the failed-closed case: a database that was unreachable at the
     * first blocks() call otherwise blocks all capture for the life of the
     * process, which is safe but means one transient blip costs the whole
     * shift's debugging.
     */
    public function invalidate(): void
    {
        $this->compiled = null;
        $this->failedAt = null;
    }

    public function add(BlocklistProvider $provider): self
    {
        $this->providers[] = $provider;
        $this->compiled = null;

        return $this;
    }

    /**
     * Whether this URL must not be captured.
     *
     * Increments the per-host counter on a match so that `wiretap doctor` can
     * show the gate is working. The host alone is recorded — no path, no
     * query, no headers. Enough to prove the rule fired; not enough to be a
     * record of the transaction.
     */
    public function blocks(string $url): bool
    {
        // A provider that loads its rules over HTTP makes that request through
        // the very hooks that ask this question, so the check arrives here
        // again while the first compile is still running — and compiles again,
        // and again, until memory runs out. The rules are not known yet, so
        // the nested request is not captured.
        if ($this->compiling) {
            return true;
        }

        foreach ($this->patterns() as $pattern) {
            if ($pattern->matches($url)) {
                $host = parse_url($url, PHP_URL_HOST);
                $key = is_string($host) ? $host : '(unparseable)';

                // Bounded. A worker checking unique hosts against a wildcard
                // rule would otherwise retain one array entry per host for the
                // life of the process — an unbounded structure inside the
                // component whose job is to stop unbounded capture.
                if (!isset($this->blockCounts[$key]) && count($this->blockCounts) >= self::MAX_COUNTED_HOSTS) {
                    $key = '(other)';
                }

                $this->blockCounts[$key] = ($this->blockCounts[$key] ?? 0) + 1;

                return true;
            }
        }

        // A provider threw while compiling. Everything is blocked until it
        // is fixed; see compile().
        return $this->failedClosed;
    }

    /**
     * @return list<Pattern>
     */
    public function patterns(): array
    {
        // A failed-closed state is held, then retried. Recompiling on every
        // call would hammer an unreachable database once per outbound request;
        // never recompiling means a blip at startup disables capture until the
        // process is restarted. Neither is what an operator wants.
        if ($this->compiled !== null
            && $this->failedClosed
            && $this->retryFailedAfterSeconds > 0
            && $this->failedAt !== null
            && (time() - $this->failedAt) >= $this->retryFailedAfterSeconds) {
            $this->compiled = null;
        }

        if ($this->compiled !== null) {
            return $this->compiled;
        }

        if ($this->compiling) {
            return [];
        }

        $this->compiling = true;

        try {
            return $this->compiled = $this->compile();
        } finally {
            $this->compiling = false;
        }
    }

    /**
     * @return list<Pattern>
     */
    private function compile(): array
    {
        $patterns = [];
        $seen = [];
        $this->errors = [];
        $this->failedClosed = false;
        $this->failedAt = null;

        foreach ($this->providers as $provider) {
            try {
                foreach ($provider->patterns() as $raw) {
                    $raw = trim($raw);

                    if ($raw === '' || str_starts_with($raw, '#')) {
                        continue;
                    }

                    if (isset($seen[$raw])) {
                        continue;
                    }

                    try {
                        $patterns[] = Pattern::compile($raw);
                        $seen[$raw] = true;
                    } catch (\InvalidArgumentException $e) {
                        // One bad line should not disable the other rules, but
                        // it must be visible: a pattern someone believes is
                        // protecting them and silently is not is the worst
                        // outcome available here.
                        $this->errors[] = sprintf('%s: %s', $provider->name(), $e->getMessage());
                    }
                }
            } catch (\Throwable $e) {
                // The provider itself failed — a database is unreachable, a
                // config file is malformed. Fail closed. A blocklist that
                // empties itself on error is worse than no blocklist.
                $this->errors[] = sprintf(
                    '%s: provider failed, blocking all traffic (%s)',
                    $provider->name(),
                    $e->getMessage(),
                );
                $this->failedClosed = true;
                $this->failedAt = time();
            }
        }

        return $patterns;
    }

    public function hasFailedClosed(): bool
    {
        $this->patterns();

        return $this->failedClosed;
    }

    /**
     * @return list<string>
     */
    public function errors(): array
    {
        $this->patterns();

        return $this->errors;
    }

    /**
     * @return array<string, int>
     */
    public function blockCounts(): array
    {
        return $this->blockCounts;
    }

    /**
     * Clear the counters. For a long-running worker that reports per job.
     */
    public function resetCounts(): void
    {
        $this->blockCounts = [];
    }

    /**
     * Provider name => pattern count, for diagnostics.
     *
     * @return array<string, int>
     */
    public function sources(): array
    {
        $sources = [];

        foreach ($this->providers as $provider) {
            try {
                $count = 0;

                foreach ($provider->patterns() as $_) {
                    ++$count;
                }

                $sources[$provider->name()] = $count;
            } catch (\Throwable) {
                // -1 signals "this provider is broken", which doctor renders
                // differently from a provider that legitimately has no rules.
                $sources[$provider->name()] = -1;
            }
        }

        return $sources;
    }
}
