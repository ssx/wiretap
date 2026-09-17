<?php

declare(strict_types=1);

use Ssx\Wiretap\Blocklist\Blocklist;
use Ssx\Wiretap\Blocklist\PresetBlocklistProvider;
use Ssx\Wiretap\CapturedBody;
use Ssx\Wiretap\Headers;
use Ssx\Wiretap\Recorder;
use Ssx\Wiretap\Redaction\RedactionConfig;
use Ssx\Wiretap\Redaction\Redactor;
use Ssx\Wiretap\Sink\NullSink;
use Ssx\Wiretap\Wiretap;

beforeEach(fn () => Wiretap::reset());
afterEach(fn () => Wiretap::reset());

describe('scoped debug in a live process', function (): void {
    beforeEach(function (): void {
        Wiretap::setRecorder(new Recorder(
            sink: new NullSink(),
            blocklist: new Blocklist([new PresetBlocklistProvider()]),
            redactor: new Redactor(),
        ));
    });

    it('keeps the blocklist that the surrounding process configured', function (): void {
        // debug() used to call fake(), which empties the blocklist. The README
        // recommends debug() for a running application, so a documented
        // production helper unblocked every payment gateway.
        Wiretap::debug(function (): void {
            expect(Wiretap::recorder()->shouldCapture('https://api.stripe.com/v1/charges'))
                ->toBeFalse();
        });
    });

    it('keeps redaction on', function (): void {
        // fake() also disables redaction, so a live key and a card number were
        // captured verbatim, ready for the next dump() or toHar().
        Wiretap::debug(function (): void {
            Wiretap::recorder()->record(exchange(
                requestHeaders: Headers::fromRaw('Authorization: Bearer sk_live_ordinarysecret'),
                requestBody: CapturedBody::captured(
                    '{"card":{"number":"4111111111111111"}}',
                    contentType: 'application/json',
                ),
            ));
        }, $calls);

        $written = json_encode($calls);

        expect($written)->not->toContain('sk_live_ordinarysecret')
            ->and($written)->not->toContain('4111111111111111');
    });

    it('still captures regardless of the global sample rate', function (): void {
        Wiretap::debug(function (): void {
            Wiretap::recorder()->record(exchange());
        }, $calls);

        expect($calls)->toHaveCount(1);
    });
});

describe('what counts as a secret', function (): void {
    it('does not learn a cookie attribute as one', function (): void {
        // Domain=, Path= and Expires= are attributes, not secrets. Learning
        // them replaced the record's own host with [REDACTED], breaking
        // `list --host`, toHost() and alwaysHosts sampling.
        $exchange = exchange(
            uri: 'https://api.example.com/v1/orders?page=2',
            responseHeaders: Headers::fromRaw(
                'Set-Cookie: sid=abc123xyzsecret; Domain=api.example.com; Path=/v1/orders; Expires=Wed, 21 Oct 2026 07:28:00 GMT'
            ),
        );

        $result = (new Redactor())->redact($exchange);

        expect($result->host())->toBe('api.example.com')
            ->and($result->uri)->toContain('/v1/orders');
    });

    it('still sweeps the cookie value itself', function (): void {
        $exchange = exchange(
            responseHeaders: Headers::fromRaw('Set-Cookie: sid=abc123xyzsecret; Path=/'),
            responseBody: CapturedBody::captured(
                '{"echo":"abc123xyzsecret"}',
                contentType: 'application/json',
            ),
        );

        expect((new Redactor())->redact($exchange)->responseBody->bytes)
            ->not->toContain('abc123xyzsecret');
    });

    it('does not treat every unlisted header as a secret in allowlist mode', function (): void {
        // isSensitiveHeader() is inverted in allowlist mode, so using it to
        // decide what to *learn* made Host and User-Agent into secrets.
        $redactor = new Redactor(new RedactionConfig(
            headerMode: RedactionConfig::MODE_ALLOW,
            headers: ['content-type'],
        ));

        $result = $redactor->redact(exchange(
            uri: 'https://api.example.com/v1/orders',
            requestHeaders: Headers::fromRaw("Host: api.example.com\r\nContent-Type: application/json"),
        ));

        expect($result->host())->toBe('api.example.com');
    });
});

describe('fail-open paths', function (): void {
    it('still strips credentials from a url parse_url cannot read', function (): void {
        // A port above 65535 makes parse_url fail. curl rejects the request,
        // but the error exchange was recorded with the token intact.
        expect((new Redactor())->redactUrl('https://example.com:99999/?token=SECRETTOKEN123'))
            ->not->toContain('SECRETTOKEN123');
    });

    it('finds a PAN written with plus-encoded spaces', function (): void {
        // http_build_query, which Guzzle's form_params uses, writes a space as
        // `+`, so the PAN pattern never matched and the safety net missed it.
        $result = (new Redactor())->redactBody(CapturedBody::captured(
            'card=4111+1111+1111+1111&cvv=123',
            contentType: 'application/x-www-form-urlencoded',
        ));

        expect($result->isPresent() ? (string) $result->bytes : '')
            ->not->toContain('4111');
    });

    it('leaves a form-encoded order reference alone', function (): void {
        $result = (new Redactor())->redactBody(CapturedBody::captured(
            'ref=1234567890123456',
            contentType: 'application/x-www-form-urlencoded',
        ));

        expect($result->bytes)->toContain('1234567890123456');
    });
});

describe('hash hints', function (): void {
    it('refuses to run unkeyed', function (): void {
        // An empty HMAC key makes the hint a public function of the plaintext:
        // two million candidates in under four seconds, so a known card BIN
        // falls in about half an hour on one core.
        expect(fn () => new RedactionConfig(hashHint: true))
            ->toThrow(InvalidArgumentException::class, 'hashSalt');
    });

    it('is allowed with a salt', function (): void {
        $config = new RedactionConfig(hashHint: true, hashSalt: 'pepper');

        expect($config->hashHint)->toBeTrue();
    });
});
