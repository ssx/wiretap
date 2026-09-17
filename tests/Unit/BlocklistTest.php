<?php

declare(strict_types=1);

use Ssx\Wiretap\Blocklist\ArrayBlocklistProvider;
use Ssx\Wiretap\Blocklist\Blocklist;
use Ssx\Wiretap\Blocklist\Pattern;
use Ssx\Wiretap\Blocklist\PresetBlocklistProvider;
use Ssx\Wiretap\Contract\BlocklistProvider;

describe('exact host patterns', function (): void {
    it('matches the host regardless of scheme or path', function (string $url): void {
        expect(Pattern::compile('api.stripe.com')->matches($url))->toBeTrue();
    })->with([
        'https://api.stripe.com/v1/charges',
        'http://api.stripe.com/',
        'https://api.stripe.com',
        'https://API.STRIPE.COM/v1/charges',
        'https://api.stripe.com:443/v1/charges',
    ]);

    it('does not match a lookalike host', function (string $url): void {
        expect(Pattern::compile('api.stripe.com')->matches($url))->toBeFalse();
    })->with([
        'https://api.stripe.com.evil.test/steal',
        'https://notapi.stripe.com/v1',
        'https://stripe.com/v1',
        'https://evil.test/?ref=api.stripe.com',
        'https://evil.test/api.stripe.com',
    ]);
});

describe('subdomain wildcards', function (): void {
    it('matches the apex and any subdomain', function (string $url): void {
        expect(Pattern::compile('*.adyen.com')->matches($url))->toBeTrue();
    })->with([
        'https://adyen.com/pal',
        'https://pal-test.adyen.com/pal/servlet/Payment',
        'https://deep.nested.adyen.com/x',
    ]);

    it('requires the dot boundary', function (string $url): void {
        expect(Pattern::compile('*.adyen.com')->matches($url))->toBeFalse();
    })->with([
        'https://notadyen.com/pal',
        'https://myadyen.com/pal',
        'https://adyen.com.evil.test/pal',
    ]);
});

describe('path prefixes', function (): void {
    $pattern = 'api.foo.com/v2/payments*';

    it('matches the prefix', function () use ($pattern): void {
        expect(Pattern::compile($pattern)->matches('https://api.foo.com/v2/payments/123'))->toBeTrue();
    });

    it('does not match a sibling path', function () use ($pattern): void {
        expect(Pattern::compile($pattern)->matches('https://api.foo.com/v2/orders'))->toBeFalse();
    });

    it('does not match the same path on another host', function () use ($pattern): void {
        expect(Pattern::compile($pattern)->matches('https://api.bar.com/v2/payments/123'))->toBeFalse();
    });
});

describe('regex patterns', function (): void {
    it('matches against the full URL', function (): void {
        $pattern = Pattern::compile('~^https://api\.foo\.com/v2/(payments|cards)~');

        expect($pattern->matches('https://api.foo.com/v2/cards/tok_1'))->toBeTrue()
            ->and($pattern->matches('https://api.foo.com/v2/orders'))->toBeFalse();
    });

    it('rejects an invalid regex at compile time rather than silently never matching', function (): void {
        expect(fn () => Pattern::compile('~^([unclosed~'))
            ->toThrow(InvalidArgumentException::class);
    });

    it('rejects a pattern missing its closing delimiter', function (): void {
        expect(fn () => Pattern::compile('~^https://api'))
            ->toThrow(InvalidArgumentException::class);
    });
});

describe('the gate', function (): void {
    it('blocks a matching url and counts it by host only', function (): void {
        $blocklist = new Blocklist([new ArrayBlocklistProvider(['*.stripe.com'])]);

        expect($blocklist->blocks('https://api.stripe.com/v1/charges?secret=abc'))->toBeTrue()
            ->and($blocklist->blocks('https://api.example.com/v1/orders'))->toBeFalse()
            ->and($blocklist->blockCounts())->toBe(['api.stripe.com' => 1]);
    });

    it('unions providers rather than intersecting them', function (): void {
        $blocklist = new Blocklist([
            new ArrayBlocklistProvider(['a.example.com'], 'first'),
            new ArrayBlocklistProvider(['b.example.com'], 'second'),
        ]);

        expect($blocklist->blocks('https://a.example.com/x'))->toBeTrue()
            ->and($blocklist->blocks('https://b.example.com/x'))->toBeTrue();
    });

    it('fails closed when a provider throws', function (): void {
        $broken = new class implements BlocklistProvider {
            public function patterns(): iterable
            {
                throw new RuntimeException('database unavailable');
            }

            public function name(): string
            {
                return 'broken';
            }
        };

        $blocklist = new Blocklist([$broken]);

        expect($blocklist->blocks('https://api.example.com/anything'))->toBeTrue()
            ->and($blocklist->hasFailedClosed())->toBeTrue()
            ->and($blocklist->errors())->toHaveCount(1);
    });

    it('keeps working when one pattern is malformed, but reports it', function (): void {
        $blocklist = new Blocklist([
            new ArrayBlocklistProvider(['~^([bad~', 'api.stripe.com']),
        ]);

        expect($blocklist->blocks('https://api.stripe.com/v1'))->toBeTrue()
            ->and($blocklist->blocks('https://api.example.com/v1'))->toBeFalse()
            ->and($blocklist->errors())->toHaveCount(1);
    });

    it('ignores blank lines and comments', function (): void {
        $blocklist = new Blocklist([
            new ArrayBlocklistProvider(['', '  ', '# a comment', 'api.stripe.com']),
        ]);

        expect($blocklist->patterns())->toHaveCount(1);
    });
});

describe('presets', function (): void {
    it('blocks the common payment gateways by default', function (string $url): void {
        $blocklist = new Blocklist([new PresetBlocklistProvider()]);

        expect($blocklist->blocks($url))->toBeTrue();
    })->with([
        'https://api.stripe.com/v1/charges',
        'https://pal-test.adyen.com/pal/servlet/Payment/authorise',
        'https://api.braintreegateway.com/merchants/x/transactions',
        'https://api-m.paypal.com/v2/checkout/orders',
        'https://api.checkout.com/payments',
    ]);

    it('blocks cloud metadata endpoints, which hand out IAM credentials', function (): void {
        $blocklist = new Blocklist([
            new PresetBlocklistProvider([PresetBlocklistProvider::CLOUD_METADATA]),
        ]);

        expect($blocklist->blocks('http://169.254.169.254/latest/meta-data/iam/security-credentials/'))
            ->toBeTrue();
    });

    it('does not block ordinary traffic', function (): void {
        $blocklist = new Blocklist([new PresetBlocklistProvider()]);

        expect($blocklist->blocks('https://api.example.com/v1/orders'))->toBeFalse();
    });

    it('rejects an unknown preset name', function (): void {
        $blocklist = new Blocklist([new PresetBlocklistProvider(['not-a-preset'])]);

        expect($blocklist->hasFailedClosed())->toBeTrue();
    });
});
