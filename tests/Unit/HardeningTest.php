<?php

declare(strict_types=1);

use Ssx\Wiretap\Blocklist\ArrayBlocklistProvider;
use Ssx\Wiretap\Blocklist\Blocklist;
use Ssx\Wiretap\Blocklist\EnvBlocklistProvider;
use Ssx\Wiretap\CapturedBody;
use Ssx\Wiretap\Headers;
use Ssx\Wiretap\Redaction\Patterns;
use Ssx\Wiretap\Redaction\RedactionConfig;
use Ssx\Wiretap\Redaction\Redactor;
use Ssx\Wiretap\TransferError;

/**
 * Each of these pins a defect found by review. They are written as the leak
 * that was possible, not as the implementation that prevents it.
 */

describe('bodies that cannot be structurally inspected', function (): void {
    it('is dropped rather than stored when a configured path cannot be applied', function (): void {
        // The real path to this: a capture layer truncates a large JSON body,
        // the prefix stops parsing, structural redaction silently does
        // nothing, and an ordinary password matches no regex detector.
        $redactor = new Redactor(new RedactionConfig(bodyPaths: ['password']));

        $result = $redactor->redactBody(CapturedBody::captured(
            '{"password":"ordinary-secret-value","other":',
            size: 200_000,
            contentType: 'application/json',
            truncated: true,
        ));

        expect($result->isPresent())->toBeFalse()
            ->and($result->omittedReason)->toBe(CapturedBody::OMITTED_REDACTED)
            ->and($result->size)->toBe(200_000);
    });

    it('keeps a body when no structural rules are configured', function (): void {
        // Nothing to apply means nothing was missed.
        $redactor = new Redactor(new RedactionConfig(bodyPaths: []));

        $result = $redactor->redactBody(CapturedBody::captured(
            '{"note":"truncated prefix',
            contentType: 'application/json',
            truncated: true,
        ));

        expect($result->isPresent())->toBeTrue();
    });

    it('can be switched back to the lossy behaviour deliberately', function (): void {
        $redactor = new Redactor(new RedactionConfig(
            bodyPaths: ['password'],
            omitUninspectableBodies: false,
        ));

        $result = $redactor->redactBody(CapturedBody::captured(
            '{"password":"ordinary-secret-value","other":',
            contentType: 'application/json',
            truncated: true,
        ));

        expect($result->isPresent())->toBeTrue();
    });
});

describe('secrets in places other than the body', function (): void {
    it('removes a credential embedded in an exception message', function (): void {
        // Guzzle puts the full request URI in the exception message, so the
        // token removed from the URI came straight back via the error.
        $exchange = exchange(
            uri: 'https://api.example.com/v1?api_key=SUPERSECRETVALUE',
            error: new TransferError(7, 'cURL error 7: failed to connect for https://api.example.com/v1?api_key=SUPERSECRETVALUE'),
        );

        $result = (new Redactor())->redact($exchange);

        expect($result->error?->message)->not->toContain('SUPERSECRETVALUE')
            ->and($result->error?->errno)->toBe(7);
    });

    it('removes a secret carried in a route path recorded as context', function (): void {
        // A framework enricher records the concrete request path, which can be
        // /reset-password/<token>.
        $exchange = exchange()->withContext(['uri' => '/reset/tok_SUPERSECRETVALUE']);

        $redactor = new Redactor(new RedactionConfig(
            patterns: ['pan' => true, 'bearer' => true, 'jwt' => true],
            custom: ['/tok_[A-Za-z0-9]+/'],
        ));

        expect($redactor->redact($exchange)->context['uri'] ?? '')
            ->not->toContain('SUPERSECRETVALUE');
    });

    it('redacts a url carried in a Location header', function (): void {
        $headers = Headers::fromRaw('Location: https://api.example.com/next?token=SUPERSECRETVALUE');

        expect((new Redactor())->redactHeaders($headers)->first('Location'))
            ->not->toContain('SUPERSECRETVALUE');
    });

    it('redacts a header value before truncating it', function (): void {
        // Truncating first kept the leading digits of a card and discarded the
        // rest, leaving a fragment no detector would ever match again.
        $padded = str_repeat('x', 4_090) . ' 4111111111111111';

        $result = (new Redactor())->redactHeaders(Headers::fromPairs([['X-Note', $padded]]));

        expect($result->first('X-Note'))->not->toContain('4111')
            ->and($result->first('X-Note'))->not->toContain('411111111111');
    });

    it('sweeps an individual cookie value echoed back in a response', function (): void {
        $exchange = exchange(
            requestHeaders: Headers::fromRaw('Cookie: session=SUPERSECRETVALUE; theme=dark'),
            responseBody: CapturedBody::captured(
                '{"session":"SUPERSECRETVALUE"}',
                contentType: 'application/json',
            ),
        );

        expect((new Redactor())->redact($exchange)->responseBody->bytes)
            ->not->toContain('SUPERSECRETVALUE');
    });

    it('redacts an array-valued sensitive query parameter', function (): void {
        // ?token[]=secret recursed into keys 0,1,2 — none of which is a
        // sensitive name — so the value survived.
        $url = (new Redactor())->redactUrl('https://api.example.com/v1?token[]=SUPERSECRETVALUE&page=2');

        expect($url)->not->toContain('SUPERSECRETVALUE')
            ->and($url)->toContain('page=2');
    });
});

describe('PAN detection with adjacent fields', function (): void {
    it('finds a card followed by another numeric field', function (): void {
        // The greedy match spans both, fails Luhn as a whole, and the card
        // inside it was never reconsidered.
        expect((new Redactor())->applyPatterns('pan 4111111111111111 cvv 123'))
            ->not->toContain('4111111111111111');
    });

    it('still leaves a same-length order reference alone', function (): void {
        expect((new Redactor())->applyPatterns('ref 1234567890123456 ok'))
            ->toContain('1234567890123456');
    });

    it('does not invent a card inside an unbroken non-card run', function (): void {
        expect(Patterns::findPans('1234567890123456'))->toBe([]);
    });

    it('returns an exact substring so replacement cannot miss', function (): void {
        $found = Patterns::findPans('4111-1111-1111-1111 123');

        expect($found)->toHaveCount(1)
            ->and(str_contains('4111-1111-1111-1111 123', $found[0]))->toBeTrue();
    });
});

describe('the safety net', function (): void {
    it('sees through JSON escaping', function (): void {
        // 1 is the digit 1. The detectors never matched the raw text.
        $redactor = new Redactor(new RedactionConfig(safetyNet: true));

        $result = $redactor->redactBody(CapturedBody::captured(
            '{"pan":"4111111111111111"}',
            contentType: 'application/json',
        ));

        expect($result->isPresent() ? (string) $result->bytes : '')
            ->not->toContain('4111111111111111');
    });
});

describe('the blocklist failing closed', function (): void {
    it('blocks when a regex fails at match time', function (): void {
        // preg_match returns false on invalid UTF-8 in the subject. Reading
        // that as "not blocked" lets through exactly what the rule exists to
        // stop.
        $blocklist = new Blocklist([
            new ArrayBlocklistProvider(['~^https://blocked\.example/.*~u']),
        ]);

        expect($blocklist->blocks("https://blocked.example/\xC3\x28"))->toBeTrue();
    });

    it('does not split a regex on the comma inside its own quantifier', function (): void {
        putenv('WIRETAP_BLOCK=~^https://example\.com/pay/[0-9]{1,3}$~');

        try {
            $blocklist = new Blocklist([new EnvBlocklistProvider()]);

            expect($blocklist->errors())->toBeEmpty()
                ->and($blocklist->blocks('https://example.com/pay/12'))->toBeTrue();
        } finally {
            putenv('WIRETAP_BLOCK');
        }
    });

    it('still splits ordinary comma-separated hosts', function (): void {
        putenv('WIRETAP_BLOCK=a.example.com, b.example.com');

        try {
            $blocklist = new Blocklist([new EnvBlocklistProvider()]);

            expect($blocklist->patterns())->toHaveCount(2)
                ->and($blocklist->blocks('https://b.example.com/x'))->toBeTrue();
        } finally {
            putenv('WIRETAP_BLOCK');
        }
    });
});

describe('header parsing', function (): void {
    it('does not turn an absolute-form request line into a header', function (): void {
        // Proxies see this form. It parsed as a header named "GET https" whose
        // value was an unredacted URL.
        $headers = Headers::fromRaw(
            "GET https://api.example.com/?token=SUPERSECRETVALUE HTTP/1.1\r\nHost: api.example.com"
        );

        expect($headers->count())->toBe(1)
            ->and($headers->first('Host'))->toBe('api.example.com')
            ->and(json_encode($headers))->not->toContain('SUPERSECRETVALUE');
    });

    it('skips a status line', function (): void {
        $headers = Headers::fromRaw("HTTP/1.1 200 OK\r\nContent-Type: application/json");

        expect($headers->count())->toBe(1)
            ->and($headers->first('Content-Type'))->toBe('application/json');
    });
});

describe('overlapping known secrets', function (): void {
    it('removes the longer secret rather than only its prefix', function (): void {
        $exchange = exchange(
            uri: 'https://api.example.com/v1?token=abcdefgh&signature=abcdefghSECRETTAIL',
            responseBody: CapturedBody::captured(
                '{"echo":"abcdefghSECRETTAIL"}',
                contentType: 'application/json',
            ),
        );

        expect((new Redactor())->redact($exchange)->responseBody->bytes)
            ->not->toContain('SECRETTAIL');
    });
});

describe('review gaps closed', function (): void {
    it('scrubs a secret echoed back in its JSON-escaped form', function (): void {
        // A token containing a slash is written as abc\/def inside a
        // serialised body, so scrubbing the raw form found nothing.
        $secret = 'abc/defghijk';

        $exchange = exchange(
            uri: 'https://api.example.com/v1?token=' . rawurlencode($secret),
            responseBody: CapturedBody::captured(
                json_encode(['echo' => $secret]),
                contentType: 'application/json',
            ),
        );

        expect((new Redactor())->redact($exchange)->responseBody->bytes)
            ->not->toContain('defghijk');
    });

    it('redacts the reason phrase and tags', function (): void {
        // Both are persisted like everything else. The reason phrase is
        // server-controlled and tags come from integrations.
        $exchange = exchange(uri: 'https://api.example.com/v1?api_key=SUPERSECRETVALUE')
            ->withReason('failed for https://api.example.com/v1?api_key=SUPERSECRETVALUE')
            ->withTags(['ref:https://api.example.com/v1?api_key=SUPERSECRETVALUE']);

        $result = (new Redactor())->redact($exchange);

        expect($result->reason)->not->toContain('SUPERSECRETVALUE')
            ->and(implode(' ', $result->tags))->not->toContain('SUPERSECRETVALUE');
    });

    it('keeps an unknown full size on a truncated capture', function (): void {
        // Reporting the prefix length as the full size made a HAR export claim
        // a 4-byte transfer for a body of unknown length.
        $body = CapturedBody::captured('abcd', size: null, truncated: true);

        expect($body->size)->toBeNull()
            ->and($body->truncated)->toBeTrue();
    });
});

describe('a broken custom redaction pattern', function (): void {
    it('is reported rather than silently skipped', function (): void {
        $redactor = new Redactor(new RedactionConfig(custom: ['/valid/', '/[unclosed/']));

        expect($redactor->invalidPatterns())->toBe(['/[unclosed/']);
    });

    it('drops bodies rather than storing what an intended rule never examined', function (): void {
        // The pattern does not compile, so it never runs. Storing the body
        // anyway leaves someone believing a rule protected it.
        $redactor = new Redactor(new RedactionConfig(custom: ['/[unclosed/']));

        $result = $redactor->redactBody(CapturedBody::captured(
            '{"note":"whatever the broken rule was meant to catch"}',
            contentType: 'application/json',
        ));

        expect($result->isPresent())->toBeFalse()
            ->and($result->omittedReason)->toBe(CapturedBody::OMITTED_REDACTED);
    });

    it('leaves bodies alone when every custom pattern compiles', function (): void {
        $redactor = new Redactor(new RedactionConfig(custom: ['/tok_[a-z0-9]+/']));

        $result = $redactor->redactBody(CapturedBody::captured(
            '{"note":"tok_abc123 and some text"}',
            contentType: 'application/json',
        ));

        expect($result->isPresent())->toBeTrue()
            ->and($result->bytes)->not->toContain('tok_abc123')
            ->and($result->bytes)->toContain('some text');
    });
});
