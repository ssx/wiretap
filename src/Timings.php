<?php

declare(strict_types=1);

namespace Ssx\Wiretap;

/**
 * Transfer timings in microseconds, as reported by curl_getinfo().
 *
 * Every field is nullable because the Guzzle middleware path cannot see most
 * of them — it knows total elapsed time and nothing about DNS or TLS. A null
 * means "not observed", never "zero".
 */
final readonly class Timings implements \JsonSerializable
{
    public function __construct(
        public ?int $dns = null,
        public ?int $connect = null,
        public ?int $tls = null,
        public ?int $ttfb = null,
        public ?int $total = null,
    ) {
    }

    /**
     * Build from a curl_getinfo() array, which reports seconds as floats.
     *
     * @param array<string, mixed> $info
     */
    public static function fromCurlInfo(array $info): self
    {
        $us = static function (string $key) use ($info): ?int {
            $value = $info[$key] ?? null;

            return is_numeric($value) ? (int) round((float) $value * 1_000_000) : null;
        };

        return new self(
            dns: $us('namelookup_time'),
            connect: $us('connect_time'),
            tls: $us('appconnect_time'),
            ttfb: $us('starttransfer_time'),
            total: $us('total_time'),
        );
    }

    public static function fromElapsedSeconds(float $seconds): self
    {
        return new self(total: (int) round($seconds * 1_000_000));
    }

    /**
     * @return array<string, int>
     */
    public function jsonSerialize(): array
    {
        return array_filter([
            'dns' => $this->dns,
            'connect' => $this->connect,
            'tls' => $this->tls,
            'ttfb' => $this->ttfb,
            'total' => $this->total,
        ], static fn (?int $v): bool => $v !== null);
    }
}
