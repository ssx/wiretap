<?php

declare(strict_types=1);

use Ssx\Wiretap\Correlation;
use Ssx\Wiretap\Support\Ulid;

beforeEach(fn () => Correlation::reset());
afterEach(fn () => Correlation::reset());

it('generates an id when there is no inbound identifier', function (): void {
    expect(Correlation::start())->toHaveLength(26);
});

it('adopts the trace id from a W3C traceparent', function (): void {
    $id = Correlation::start('00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01');

    expect($id)->toBe('4bf92f3577b34da6a3ce929d0e0e4736');
});

it('accepts an opaque request id', function (): void {
    expect(Correlation::start('req-abc-123'))->toBe('req-abc-123');
});

it('strips characters that would complicate storage', function (): void {
    expect(Correlation::start("bad\nid with spaces"))->toBe('badidwithspaces');
});

it('falls back to a generated id when the inbound value is empty', function (): void {
    expect(Correlation::start('   '))->toHaveLength(26);
});

it('numbers calls monotonically within one correlation', function (): void {
    Correlation::start('fixed');

    expect([
        Correlation::nextSequence(),
        Correlation::nextSequence(),
        Correlation::nextSequence(),
    ])->toBe([0, 1, 2]);
});

it('resets the sequence when a new correlation starts', function (): void {
    Correlation::start('first');
    Correlation::nextSequence();
    Correlation::nextSequence();

    Correlation::start('second');

    expect(Correlation::nextSequence())->toBe(0);
});

it('produces ulids that sort by creation time', function (): void {
    $earlier = Ulid::generate(1_700_000_000.0);
    $later = Ulid::generate(1_800_000_000.0);

    expect(strcmp($earlier, $later))->toBeLessThan(0);
});

it('reports whether a correlation is in scope without creating one', function (): void {
    // id() generates on demand, so asking it would always answer "yes".
    expect(Correlation::hasStarted())->toBeFalse();

    Correlation::start('scoped');

    expect(Correlation::hasStarted())->toBeTrue();

    Correlation::reset();

    expect(Correlation::hasStarted())->toBeFalse();
});
