<?php

declare(strict_types=1);

use Ssx\Wiretap\TransferClaim;
use Ssx\Wiretap\Wiretap;

beforeEach(fn () => TransferClaim::reset());
afterEach(fn () => TransferClaim::reset());

it('is not honoured until the curl hooks say so', function (): void {
    expect(TransferClaim::isHonoured())->toBeFalse();

    TransferClaim::honour();

    expect(TransferClaim::isHonoured())->toBeTrue();
});

it('survives a Wiretap reset, because the hooks it describes do', function (): void {
    TransferClaim::honour();
    Wiretap::reset();

    expect(TransferClaim::isHonoured())->toBeTrue();
});

it('is a request option name, never a curl option', function (): void {
    // An int key would be read as a curl option: Guzzle deprecates unknown
    // ones from 7.12 and ext-curl throws for them.
    expect(TransferClaim::KEY)->toBeString()
        ->and(is_numeric(TransferClaim::KEY))->toBeFalse()
        ->and(defined(TransferClaim::class . '::OPTION'))->toBeFalse();
});
