<?php

declare(strict_types=1);

namespace Ssx\Wiretap;

/**
 * Decides whether an exchange is kept.
 *
 * Sampling is deterministic on the correlation id, never per call. Random
 * per-call sampling gives you half a conversation, which for debugging is
 * worse than nothing — you cannot tell whether the call you are missing
 * happened and was dropped, or never happened.
 *
 * Almost all of the value is in the overrides: one percent of everything
 * plus one hundred percent of failures is the right production default.
 */
final readonly class Sampler
{
    /**
     * @param int          $rateBasisPoints 10000 = keep everything, 100 = 1%
     * @param list<string> $alwaysHosts     Hosts always kept regardless of rate
     */
    public function __construct(
        private int $rateBasisPoints = 10000,
        private bool $alwaysKeepFailures = true,
        private ?int $slowThresholdUs = null,
        private array $alwaysHosts = [],
    ) {
    }

    public function shouldKeep(Exchange $exchange): bool
    {
        if ($this->alwaysKeepFailures && $exchange->failed()) {
            return true;
        }

        if ($this->slowThresholdUs !== null
            && $exchange->timings->total !== null
            && $exchange->timings->total >= $this->slowThresholdUs) {
            return true;
        }

        $host = $exchange->host();

        if ($host !== null) {
            foreach ($this->alwaysHosts as $always) {
                if (strcasecmp($host, $always) === 0) {
                    return true;
                }
            }
        }

        return $this->sampledIn($exchange->correlationId);
    }

    private function sampledIn(string $correlationId): bool
    {
        if ($this->rateBasisPoints >= 10000) {
            return true;
        }

        if ($this->rateBasisPoints <= 0) {
            return false;
        }

        return (crc32($correlationId) % 10000) < $this->rateBasisPoints;
    }
}
