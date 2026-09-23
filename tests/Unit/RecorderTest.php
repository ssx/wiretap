<?php

declare(strict_types=1);

use Ssx\Wiretap\Blocklist\ArrayBlocklistProvider;
use Ssx\Wiretap\Blocklist\Blocklist;
use Ssx\Wiretap\CapturedBody;
use Ssx\Wiretap\Contract\ContextEnricher;
use Ssx\Wiretap\Contract\ExchangeSink;
use Ssx\Wiretap\Exchange;
use Ssx\Wiretap\Headers;
use Ssx\Wiretap\Recorder;
use Ssx\Wiretap\Sampler;
use Ssx\Wiretap\Sink\InMemorySink;
use Ssx\Wiretap\Timings;

describe('the capture gate', function (): void {
    it('refuses to capture a blocked url before any body is read', function (): void {
        $recorder = new Recorder(
            sink: new InMemorySink(),
            blocklist: new Blocklist([new ArrayBlocklistProvider(['*.stripe.com'])]),
        );

        expect($recorder->shouldCapture('https://api.stripe.com/v1/charges'))->toBeFalse()
            ->and($recorder->shouldCapture('https://api.example.com/v1/orders'))->toBeTrue();
    });

    it('drops a blocked exchange even if a capture layer records it anyway', function (): void {
        $sink = new InMemorySink();
        $recorder = new Recorder(
            sink: $sink,
            blocklist: new Blocklist([new ArrayBlocklistProvider(['*.stripe.com'])]),
        );

        $recorder->record(exchange(uri: 'https://api.stripe.com/v1/charges'));
        $recorder->flush();

        expect($sink->all())->toBeEmpty();
    });

    it('catches a redirect onto a blocked host', function (): void {
        $sink = new InMemorySink();
        $recorder = new Recorder(
            sink: $sink,
            blocklist: new Blocklist([new ArrayBlocklistProvider(['*.stripe.com'])]),
        );

        // shouldCapture() passed on the original host; the effective URL is
        // what ends up on the record.
        expect($recorder->shouldCapture('https://redirector.example.com/go'))->toBeTrue();

        $recorder->record(exchange(uri: 'https://api.stripe.com/v1/charges'));
        $recorder->flush();

        expect($sink->all())->toBeEmpty();
    });
});

describe('recording', function (): void {
    it('redacts before the record reaches the sink', function (): void {
        $sink = new InMemorySink();
        $recorder = new Recorder(sink: $sink);

        $recorder->record(exchange(
            uri: 'https://api.example.com/v1?api_key=SECRET',
            requestHeaders: Headers::fromRaw('Authorization: Bearer TOPSECRET'),
        ));
        $recorder->flush();

        $written = json_encode($sink->all()[0]);

        expect($written)->not->toContain('SECRET')
            ->and($written)->not->toContain('TOPSECRET');
    });

    it('applies enrichers in order', function (): void {
        $sink = new InMemorySink();
        $recorder = new Recorder(sink: $sink);

        $recorder->addEnricher(new class implements ContextEnricher {
            public function enrich(Exchange $exchange): Exchange
            {
                return $exchange->withContext(['route' => 'checkout.place']);
            }
        });

        $recorder->record(exchange());
        $recorder->flush();

        expect($sink->all()[0]->context)->toBe(['route' => 'checkout.place']);
    });

    it('never lets a failing sink reach the application', function (): void {
        $exploding = new class implements ExchangeSink {
            public function write(Exchange $exchange): void
            {
                throw new RuntimeException('disk full');
            }

            public function writeBatch(iterable $exchanges): void
            {
                throw new RuntimeException('disk full');
            }
        };

        $recorder = new Recorder(sink: $exploding);
        $recorder->record(exchange());

        expect(fn () => $recorder->flush())->not->toThrow(Throwable::class);
    });

    it('does nothing when disabled', function (): void {
        $sink = new InMemorySink();
        $recorder = new Recorder(sink: $sink, enabled: false);

        $recorder->record(exchange());
        $recorder->flush();

        expect($sink->all())->toBeEmpty()
            ->and($recorder->shouldCapture('https://api.example.com/x'))->toBeFalse();
    });

    it('does not recurse when a sink makes its own http call', function (): void {
        $sink = new class implements ExchangeSink {
            public int $writes = 0;

            public ?Recorder $recorder = null;

            public function write(Exchange $exchange): void
            {
                ++$this->writes;
                // A sink shipping records to a collector would be captured by
                // our own hooks. Simulate that re-entry.
                $this->recorder?->record(exchange(uri: 'https://collector.example.com/ingest'));
            }

            public function writeBatch(iterable $exchanges): void
            {
                foreach ($exchanges as $exchange) {
                    $this->write($exchange);
                }
            }
        };

        $recorder = new Recorder(sink: $sink);
        $sink->recorder = $recorder;

        $recorder->record(exchange());
        $recorder->flush();

        expect($sink->writes)->toBe(1);
    });
});

describe('buffering', function (): void {
    it('flushes automatically once the record threshold is reached', function (): void {
        $sink = new InMemorySink();
        $recorder = new Recorder(sink: $sink, maxBufferedRecords: 3);

        foreach (range(1, 2) as $i) {
            $recorder->record(exchange(uri: "https://api.example.com/v1/orders/{$i}"));
        }

        expect($sink->all())->toHaveCount(0);

        // The third record reaches the threshold and is written with the
        // first two, rather than waiting for a fourth to push it out.
        $recorder->record(exchange(uri: 'https://api.example.com/v1/orders/3'));

        expect($sink->all())->toHaveCount(3)
            ->and($recorder->buffered())->toBe([]);
    });

    it('writes every record as it is recorded when the threshold is one', function (): void {
        $sink = new class implements ExchangeSink {
            public int $batches = 0;

            /** @var list<Exchange> */
            public array $written = [];

            public function write(Exchange $exchange): void
            {
                $this->writeBatch([$exchange]);
            }

            public function writeBatch(iterable $exchanges): void
            {
                ++$this->batches;

                foreach ($exchanges as $exchange) {
                    $this->written[] = $exchange;
                }
            }
        };

        $recorder = new Recorder(sink: $sink, maxBufferedRecords: 1);

        $recorder->record(exchange(uri: 'https://api.example.com/v1/orders/1'));

        // Written immediately, not held until the next record arrives.
        expect($sink->written)->toHaveCount(1)
            ->and($recorder->buffered())->toBe([]);

        $recorder->record(exchange(uri: 'https://api.example.com/v1/orders/2'));
        $recorder->flush();

        // One write per record, and the explicit flush has nothing to add.
        expect($sink->written)->toHaveCount(2)
            ->and($sink->batches)->toBe(2);
    });

    it('still swallows a failing sink when the threshold flushes', function (): void {
        $sink = new class implements ExchangeSink {
            public int $attempts = 0;

            public function write(Exchange $exchange): void
            {
                $this->writeBatch([$exchange]);
            }

            public function writeBatch(iterable $exchanges): void
            {
                ++$this->attempts;

                throw new RuntimeException('disk full');
            }
        };

        $recorder = new Recorder(sink: $sink, maxBufferedRecords: 1);

        $recorder->record(exchange());
        $recorder->record(exchange());

        expect($sink->attempts)->toBe(2)
            ->and($recorder->buffered())->toBe([]);
    });

    it('bounds total buffered bytes rather than growing without limit', function (): void {
        $sink = new InMemorySink();
        $recorder = new Recorder(
            sink: $sink,
            maxBufferedRecords: 1000,
            maxBufferedBytes: 2000,
        );

        $big = CapturedBody::captured(str_repeat('a', 1500), contentType: 'text/plain');

        foreach (range(1, 5) as $i) {
            $recorder->record(exchange(uri: "https://api.example.com/{$i}", requestBody: $big));
        }

        expect(count($recorder->buffered()))->toBeLessThan(5);
    });
});

describe('sampling', function (): void {
    it('keeps failures regardless of the sample rate', function (): void {
        $sampler = new Sampler(rateBasisPoints: 0, alwaysKeepFailures: true);

        expect($sampler->shouldKeep(exchange(status: 500)))->toBeTrue()
            ->and($sampler->shouldKeep(exchange(status: 200)))->toBeFalse();
    });

    it('keeps slow calls', function (): void {
        $sampler = new Sampler(rateBasisPoints: 0, slowThresholdUs: 1_000_000);

        expect($sampler->shouldKeep(exchange(timings: new Timings(total: 2_000_000))))->toBeTrue()
            ->and($sampler->shouldKeep(exchange(timings: new Timings(total: 10))))->toBeFalse();
    });

    it('keeps watched hosts', function (): void {
        $sampler = new Sampler(rateBasisPoints: 0, alwaysHosts: ['api.example.com']);

        expect($sampler->shouldKeep(exchange(uri: 'https://api.example.com/v1')))->toBeTrue()
            ->and($sampler->shouldKeep(exchange(uri: 'https://other.example.com/v1')))->toBeFalse();
    });

    it('decides consistently for every call in one correlation', function (): void {
        $sampler = new Sampler(rateBasisPoints: 5000, alwaysKeepFailures: false);

        // Random per-call sampling would give half a conversation, which is
        // useless for debugging. Same correlation id must give same answer.
        $decisions = array_map(
            static fn (int $i): bool => $sampler->shouldKeep(
                exchange(uri: "https://api.example.com/{$i}", correlationId: 'fixed-id')
            ),
            range(1, 20),
        );

        expect(array_unique($decisions))->toHaveCount(1);
    });
});
