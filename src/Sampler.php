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
     * @param string|null  $samplingSalt    Per-install secret; see sampledIn()
     */
    public function __construct(
        private int $rateBasisPoints = 10000,
        private bool $alwaysKeepFailures = true,
        private ?int $slowThresholdUs = null,
        private array $alwaysHosts = [],
        private ?string $samplingSalt = null,
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

    /**
     * The sampling decision for a correlation id.
     *
     * With a salt, the key is an HMAC of the id rather than the id itself.
     *
     * The id is frequently not ours: the framework bridges adopt an inbound
     * traceparent or X-Request-Id so a trace joins up with whatever called us,
     * which is the whole point of accepting the header. But that makes the
     * sampling key caller-controlled, and the decision is a pure function of
     * it — so below 100% a caller could try header values until their own
     * traffic reliably landed on the not-sampled side, and stay out of the
     * capture on demand. They could equally collide with another request's id.
     *
     * Hashing fixes that without giving anything up. The recorded id is still
     * exactly what arrived, so traces still join; only the key the decision is
     * computed from changes, and without the salt it cannot be predicted. The
     * decision stays deterministic and stable for a given id and salt, which
     * is what keeps one conversation whole.
     *
     * No salt means the id is used directly, which is the previous behaviour
     * and fine where nothing untrusted reaches the correlation id.
     */
    private function sampledIn(string $correlationId): bool
    {
        if ($this->rateBasisPoints >= 10000) {
            return true;
        }

        if ($this->rateBasisPoints <= 0) {
            return false;
        }

        $key = $this->samplingSalt === null || $this->samplingSalt === ''
            ? $correlationId
            : hash_hmac('sha256', $correlationId, $this->samplingSalt);

        return (crc32($key) % 10000) < $this->rateBasisPoints;
    }
}
