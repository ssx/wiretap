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

it('uses a key no curl option can have', function (): void {
    expect(TransferClaim::OPTION)->toBeLessThan(-1)
        ->and(TransferClaim::OPTION)->toBeGreaterThanOrEqual(-2147483648);

    if (!extension_loaded('curl')) {
        return;
    }

    $clashes = array_keys(array_filter(
        get_defined_constants(true)['curl'] ?? [],
        static fn (mixed $value, string $name): bool => $value === TransferClaim::OPTION && str_starts_with($name, 'CURLOPT_'),
        ARRAY_FILTER_USE_BOTH,
    ));

    expect($clashes)->toBe([]);
});

it('is rejected by curl itself, which is why it must never reach it unhooked', function (): void {
    if (!extension_loaded('curl')) {
        $this->markTestSkipped('needs ext-curl');
    }

    $handle = curl_init();

    expect(fn () => curl_setopt($handle, TransferClaim::OPTION, true))->toThrow(\ValueError::class);
});
