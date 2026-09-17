<?php

declare(strict_types=1);

use Ssx\Wiretap\Blocklist\ArrayBlocklistProvider;
use Ssx\Wiretap\Blocklist\Blocklist;
use Ssx\Wiretap\Exchange;
use Ssx\Wiretap\Testing\AssertionFailed;
use Ssx\Wiretap\Testing\RecordedCalls;
use Ssx\Wiretap\Wiretap;

beforeEach(fn () => Wiretap::reset());
afterEach(fn () => Wiretap::reset());

describe('faking', function (): void {
    it('captures in memory and keeps everything', function (): void {
        Wiretap::fake();

        Wiretap::recorder()->record(exchange(uri: 'https://api.example.com/v1/orders'));

        expect(Wiretap::recorded())->toHaveCount(1)
            ->and(Wiretap::isFaked())->toBeTrue();
    });

    it('does not redact while faking, so assertions can see real values', function (): void {
        Wiretap::fake();

        Wiretap::recorder()->record(exchange(uri: 'https://api.example.com/v1?api_key=SECRET'));

        // Asserting on a value the redactor would have replaced is the whole
        // point of a test double.
        expect(Wiretap::recorded()->first()->uri)->toContain('SECRET');
    });

    it('starts with an empty blocklist so a payment call is still assertable', function (): void {
        // The payment-gateways preset is on by default in production. Applying
        // it here would silently drop the call a test is trying to assert on.
        Wiretap::fake();

        Wiretap::recorder()->record(exchange(uri: 'https://api.stripe.com/v1/charges'));

        expect(Wiretap::recorded())->toHaveCount(1);
    });

    it('honours a blocklist when one is passed deliberately', function (): void {
        Wiretap::fake(new Blocklist([new ArrayBlocklistProvider(['*.stripe.com'])]));

        Wiretap::recorder()->record(exchange(uri: 'https://api.stripe.com/v1/charges'));

        expect(Wiretap::recorded())->toBeEmpty();
    });

    it('explains itself when assertions run without fake()', function (): void {
        expect(fn () => Wiretap::recorded())
            ->toThrow(AssertionFailed::class, 'Wiretap::fake() must be called before assertions');
    });
});

describe('assertions', function (): void {
    beforeEach(function (): void {
        Wiretap::fake();

        Wiretap::recorder()->record(exchange(uri: 'https://api.example.com/v1/orders', method: 'POST', status: 201));
        Wiretap::recorder()->record(exchange(uri: 'https://api.example.com/v1/orders/1', method: 'GET', status: 200));
        Wiretap::recorder()->record(exchange(uri: 'https://other.example.com/v1/ping', method: 'GET', status: 500));
    });

    it('asserts a request was sent to a host', function (): void {
        Wiretap::assertSent('api.example.com');

        expect(true)->toBeTrue();
    });

    it('asserts against a callback', function (): void {
        Wiretap::assertSent(fn (Exchange $e): bool => $e->method === 'POST' && $e->status === 201);

        expect(true)->toBeTrue();
    });

    it('asserts an exact count', function (): void {
        Wiretap::assertSent('api.example.com', times: 2);
        Wiretap::assertSentCount(3);

        expect(true)->toBeTrue();
    });

    it('asserts nothing was sent to a host', function (): void {
        Wiretap::assertNothingSentTo('api.stripe.com');

        expect(true)->toBeTrue();
    });

    it('fails with the recorded calls listed in the message', function (): void {
        // Without this, the first thing anyone does is add a dump() and rerun.
        try {
            Wiretap::assertSent('never-called.example.com');
            expect(false)->toBeTrue('the assertion should have failed');
        } catch (\Throwable $e) {
            expect($e->getMessage())->toContain('never-called.example.com')
                ->and($e->getMessage())->toContain('Recorded:')
                ->and($e->getMessage())->toContain('https://api.example.com/v1/orders')
                ->and($e->getMessage())->toContain('https://other.example.com/v1/ping');
        }
    });

    it('fails a count assertion with the actual number', function (): void {
        try {
            Wiretap::assertSentCount(99);
            expect(false)->toBeTrue('the assertion should have failed');
        } catch (\Throwable $e) {
            expect($e->getMessage())->toContain('Expected 99')
                ->and($e->getMessage())->toContain('3 were sent');
        }
    });
});

describe('filtering recorded calls', function (): void {
    beforeEach(function (): void {
        Wiretap::fake();
        Wiretap::recorder()->record(exchange(uri: 'https://a.example.com/one', method: 'POST', status: 201));
        Wiretap::recorder()->record(exchange(uri: 'https://b.example.com/two', method: 'GET', status: 500));
        Wiretap::recorder()->record(exchange(uri: 'https://a.example.com/three', method: 'GET', status: 200));
    });

    it('filters by host, method and status', function (): void {
        $calls = Wiretap::recorded();

        expect($calls->toHost('a.example.com'))->toHaveCount(2)
            ->and($calls->withMethod('GET'))->toHaveCount(2)
            ->and($calls->withStatus(500))->toHaveCount(1)
            ->and($calls->failed())->toHaveCount(1);
    });

    it('exposes first, last and index access', function (): void {
        $calls = Wiretap::recorded();

        expect($calls->first()->uri)->toContain('/one')
            ->and($calls->last()->uri)->toContain('/three')
            ->and($calls->get(1)->uri)->toContain('/two')
            ->and($calls->get(99))->toBeNull();
    });

    it('exports the capture as HAR', function (): void {
        $har = json_decode(Wiretap::recorded()->toHar(), true);

        expect($har['log']['version'])->toBe('1.2')
            ->and($har['log']['entries'])->toHaveCount(3);
    });

    it('describes an empty capture without blowing up', function (): void {
        expect((new RecordedCalls())->describe())->toBe('(nothing was recorded)');
    });
});

describe('scoped debug', function (): void {
    it('captures only what happened inside the closure', function (): void {
        $recorder = Wiretap::recorder();

        $result = Wiretap::debug(function (): string {
            Wiretap::recorder()->record(exchange(uri: 'https://inside.example.com/call'));

            return 'returned';
        }, $calls);

        expect($result)->toBe('returned')
            ->and($calls)->toHaveCount(1)
            ->and($calls->first()->uri)->toContain('inside.example.com')
            // The global recorder must be exactly as it was.
            ->and(Wiretap::recorder())->toBe($recorder)
            ->and(Wiretap::isFaked())->toBeFalse();
    });

    it('restores the previous recorder even when the closure throws', function (): void {
        $recorder = Wiretap::recorder();

        try {
            Wiretap::debug(function (): void {
                throw new RuntimeException('boom');
            });
        } catch (RuntimeException) {
            // expected
        }

        expect(Wiretap::recorder())->toBe($recorder)
            ->and(Wiretap::isFaked())->toBeFalse();
    });

    it('works inside an existing fake without destroying it', function (): void {
        Wiretap::fake();
        Wiretap::recorder()->record(exchange(uri: 'https://outer.example.com/a'));

        Wiretap::debug(function (): void {
            Wiretap::recorder()->record(exchange(uri: 'https://inner.example.com/b'));
        }, $inner);

        expect($inner)->toHaveCount(1)
            ->and($inner->first()->uri)->toContain('inner.example.com')
            ->and(Wiretap::recorded())->toHaveCount(1)
            ->and(Wiretap::recorded()->first()->uri)->toContain('outer.example.com');
    });
});
