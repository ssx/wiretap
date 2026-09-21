<?php

declare(strict_types=1);

use Ssx\Wiretap\CapturedBody;
use Ssx\Wiretap\Exchange;
use Ssx\Wiretap\Headers;
use Ssx\Wiretap\Sampler;
use Ssx\Wiretap\Timings;

function sampled(string $correlationId, string $host = 'api.example.com'): Exchange
{
    return new Exchange(
        id: 'x',
        correlationId: $correlationId,
        transport: 'curl',
        method: 'GET',
        uri: "https://{$host}/v1",
        requestHeaders: Headers::empty(),
        requestBody: CapturedBody::none(),
        status: 200,
        reason: 'OK',
        responseHeaders: Headers::empty(),
        responseBody: CapturedBody::none(),
        timings: new Timings(total: 1),
        error: null,
        startedAt: 1.0,
    );
}

describe('the sampling key', function (): void {
    it('lets anyone choose their own outcome when there is no salt', function (): void {
        // The decision is a pure function of the correlation id, and the
        // bridges adopt an inbound traceparent or X-Request-Id so a trace
        // joins up with the caller. That makes the key caller-controlled:
        // anyone who knows the algorithm can compute an id offline that lands
        // wherever they want, and below 100% that means opting their own
        // traffic out of the capture.
        $rate = 100;
        $sampler = new Sampler(rateBasisPoints: $rate, alwaysKeepFailures: false);

        $chosen = null;

        for ($i = 0; $i < 100_000; ++$i) {
            if ((crc32("chosen-{$i}") % 10000) < $rate) {
                $chosen = "chosen-{$i}";

                break;
            }
        }

        expect($chosen)->not->toBeNull()
            ->and($sampler->shouldKeep(sampled((string) $chosen)))->toBeTrue();
    });

    it('makes that computation useless once a salt is set', function (): void {
        // Stated as the property, not as one outcome. A single id proves
        // little: at a 1% rate the salted key lands in the sampled-in bucket
        // 1% of the time by chance, so an assertion on one id is a coin that
        // usually comes up the way you wanted. The sibling test in
        // ssx/wiretap-laravel was written that way and failed on CI once the
        // salt was a per-run value.
        $rate = 100;
        $salted = new Sampler(
            rateBasisPoints: $rate,
            alwaysKeepFailures: false,
            samplingSalt: 'per-install-secret',
        );
        $unsalted = new Sampler(rateBasisPoints: $rate, alwaysKeepFailures: false);

        $chosen = [];

        for ($i = 0; count($chosen) < 200 && $i < 1_000_000; ++$i) {
            if ((crc32("chosen-{$i}") % 10000) < $rate) {
                $chosen[] = "chosen-{$i}";
            }
        }

        $unsaltedKept = 0;
        $saltedKept = 0;

        foreach ($chosen as $id) {
            $unsaltedKept += $unsalted->shouldKeep(sampled($id)) ? 1 : 0;
            $saltedKept += $salted->shouldKeep(sampled($id)) ? 1 : 0;
        }

        // Every one, by construction — offline computation is exactly right
        // without a salt.
        expect($unsaltedKept)->toBe(200)
            // And worth no more than chance with one. ~2 expected at 1%.
            ->and($saltedKept)->toBeLessThan(40);
    });

    it('stays deterministic for one id, which is what keeps a trace whole', function (): void {
        $sampler = new Sampler(rateBasisPoints: 5000, alwaysKeepFailures: false, samplingSalt: 'secret');

        $first = $sampler->shouldKeep(sampled('one-conversation'));

        for ($i = 0; $i < 20; ++$i) {
            expect($sampler->shouldKeep(sampled('one-conversation')))->toBe($first);
        }
    });

    it('honours the configured rate', function (): void {
        // Hashing must not skew the distribution; the salt changes which ids
        // are kept, not how many.
        $salted = new Sampler(rateBasisPoints: 1000, alwaysKeepFailures: false, samplingSalt: 'secret');

        $kept = 0;

        for ($i = 0; $i < 20_000; ++$i) {
            if ($salted->shouldKeep(sampled("id-{$i}"))) {
                ++$kept;
            }
        }

        // 10% of 20000 is 2000; allow generous slack for a hash distribution.
        expect($kept)->toBeGreaterThan(1600)->toBeLessThan(2400);
    });

    it('gives different installs different decisions for the same id', function (): void {
        $a = new Sampler(rateBasisPoints: 5000, alwaysKeepFailures: false, samplingSalt: 'install-a');
        $b = new Sampler(rateBasisPoints: 5000, alwaysKeepFailures: false, samplingSalt: 'install-b');

        $differs = false;

        for ($i = 0; $i < 200; ++$i) {
            if ($a->shouldKeep(sampled("id-{$i}")) !== $b->shouldKeep(sampled("id-{$i}"))) {
                $differs = true;

                break;
            }
        }

        expect($differs)->toBeTrue();
    });

    it('behaves exactly as before when no salt is given', function (): void {
        // Unsalted is still the documented default, and fine wherever nothing
        // untrusted reaches the correlation id.
        $sampler = new Sampler(rateBasisPoints: 5000, alwaysKeepFailures: false);

        foreach (['a', 'b', 'c', 'correlation-id'] as $id) {
            expect($sampler->shouldKeep(sampled($id)))->toBe((crc32($id) % 10000) < 5000);
        }
    });

    it('treats an empty salt as no salt rather than hashing with nothing', function (): void {
        $empty = new Sampler(rateBasisPoints: 5000, alwaysKeepFailures: false, samplingSalt: '');
        $none = new Sampler(rateBasisPoints: 5000, alwaysKeepFailures: false);

        foreach (['a', 'b', 'c'] as $id) {
            expect($empty->shouldKeep(sampled($id)))->toBe($none->shouldKeep(sampled($id)));
        }
    });

    it('does not change the always-keep rules', function (): void {
        $sampler = new Sampler(
            rateBasisPoints: 0,
            alwaysKeepFailures: false,
            alwaysHosts: ['api.example.com'],
            samplingSalt: 'secret',
        );

        expect($sampler->shouldKeep(sampled('anything')))->toBeTrue()
            ->and($sampler->shouldKeep(sampled('anything', 'other.example.com')))->toBeFalse();
    });
});
