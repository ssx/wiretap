<?php

declare(strict_types=1);

use Ssx\Wiretap\Blocklist\ArrayBlocklistProvider;
use Ssx\Wiretap\Blocklist\Blocklist;
use Ssx\Wiretap\Blocklist\EnvBlocklistProvider;
use Ssx\Wiretap\Blocklist\PresetBlocklistProvider;

/**
 * Three ways the gate let blocked traffic through. A gate that fails open is
 * the worst defect class in this package, so each is written as the request
 * that got past it.
 */

describe('scheme-less urls', function (): void {
    it('blocks a url curl would send but parse_url reads as a path', function (): void {
        // curl accepts this and defaults to http. parse_url sees no host, and
        // the payment-gateways preset simply did not fire.
        expect((new Blocklist([new PresetBlocklistProvider()]))->blocks('api.stripe.com/v1/charges'))
            ->toBeTrue();
    });

    it('blocks an address it cannot parse at all', function (): void {
        // A rule exists to stop this traffic, so something unreadable is
        // blocked rather than waved through.
        // parse_url returns false for this one. Note that many
        // strange-looking URLs do parse — `http://:::::` yields host '::::'
        // — so the unparseable case is narrower than it first appears.
        expect((new Blocklist([new ArrayBlocklistProvider(['api.stripe.com'])]))->blocks('http://'))
            ->toBeTrue();
    });

    it('still lets ordinary traffic through', function (): void {
        expect((new Blocklist([new PresetBlocklistProvider()]))->blocks('https://api.example.com/v1/orders'))
            ->toBeFalse();
    });
});

describe('an unterminated regex in the env variable', function (): void {
    it('does not swallow the rules that follow it', function (): void {
        // A missing closing tilde made the whole remainder one token: zero
        // rules parsed, nothing blocked, and hasFailedClosed() false — a typo
        // in the first rule silently disabled every rule after it.
        putenv('WIRETAP_BLOCK=~^https://pay.example.com/,api.secret.com,*.bank.com');

        try {
            $blocklist = new Blocklist([new EnvBlocklistProvider()]);

            expect($blocklist->blocks('https://api.secret.com/x'))->toBeTrue()
                ->and($blocklist->blocks('https://vault.bank.com/x'))->toBeTrue()
                // The broken rule is still reported, which is the part someone
                // can act on.
                ->and($blocklist->errors())->not->toBeEmpty();
        } finally {
            putenv('WIRETAP_BLOCK');
        }
    });
});

describe('path prefix rules', function (): void {
    $rule = 'api.foo.com/v2/payments*';

    it('matches the path curl actually sends', function (string $path) use ($rule): void {
        // curl resolves dot-segments before sending, so these are all
        // /v2/payments on the wire while a literal comparison saw four
        // different strings.
        $blocklist = new Blocklist([new ArrayBlocklistProvider([$rule])]);

        expect($blocklist->blocks('https://api.foo.com' . $path))->toBeTrue();
    })->with([
        '/v2/payments/1',
        '/v2/../v2/payments/1',
        '//v2/payments/1',
        '/V2/payments/1',
        '/v2/%70ayments/1',
        '/v2/payments/',
    ]);

    it('does not start matching paths it should not', function (string $path) use ($rule): void {
        $blocklist = new Blocklist([new ArrayBlocklistProvider([$rule])]);

        expect($blocklist->blocks('https://api.foo.com' . $path))->toBeFalse();
    })->with([
        '/v2/orders',
        '/v20/payments',
        '/v2',
    ]);
});
