<?php

declare(strict_types=1);

use Ssx\Wiretap\CapturedBody;
use Ssx\Wiretap\Headers;
use Ssx\Wiretap\Redaction\KnownSecrets;
use Ssx\Wiretap\Redaction\RedactionConfig;
use Ssx\Wiretap\Redaction\Redactor;

describe('echoed secrets', function (): void {
    it('removes a query-string secret from a response body that echoes it', function (): void {
        // httpbin and most REST APIs that return the created resource do
        // exactly this: hand your own input straight back.
        $exchange = exchange(
            uri: 'https://api.example.com/v1?api_key=SUPERSECRETVALUE',
            responseBody: CapturedBody::captured(
                json_encode(['args' => ['api_key' => 'SUPERSECRETVALUE']]),
                contentType: 'application/json',
            ),
        );

        $result = (new Redactor())->redact($exchange);

        expect($result->uri)->not->toContain('SUPERSECRETVALUE')
            ->and($result->responseBody->bytes)->not->toContain('SUPERSECRETVALUE');
    });

    it('removes a bearer token echoed back without its scheme', function (): void {
        $exchange = exchange(
            requestHeaders: Headers::fromRaw('Authorization: Bearer tok_abcdefghijklmnop'),
            responseBody: CapturedBody::captured(
                json_encode(['echoed_token' => 'tok_abcdefghijklmnop']),
                contentType: 'application/json',
            ),
        );

        $result = (new Redactor())->redact($exchange);

        expect($result->responseBody->bytes)->not->toContain('tok_abcdefghijklmnop');
    });

    it('catches a url-encoded form of the same secret', function (): void {
        $secret = 'abc+def/ghi=jkl';

        $exchange = exchange(
            uri: 'https://api.example.com/v1?signature=' . rawurlencode($secret),
            responseBody: CapturedBody::captured(
                json_encode(['sig' => rawurlencode($secret)]),
                contentType: 'application/json',
            ),
        );

        $result = (new Redactor())->redact($exchange);

        expect($result->responseBody->bytes)->not->toContain(rawurlencode($secret));
    });

    it('decodes basic auth and removes both halves', function (): void {
        $exchange = exchange(
            requestHeaders: Headers::fromRaw('Authorization: Basic ' . base64_encode('alice:hunter2pass')),
            responseBody: CapturedBody::captured(
                json_encode(['user' => 'alice', 'pass' => 'hunter2pass']),
                contentType: 'application/json',
            ),
        );

        $result = (new Redactor())->redact($exchange);

        expect($result->responseBody->bytes)->not->toContain('hunter2pass');
    });

    it('leaves short values alone so the log stays readable', function (): void {
        // Sweeping every occurrence of a three-character token would corrupt
        // unrelated content — which is how redaction ends up switched off.
        $exchange = exchange(
            uri: 'https://api.example.com/v1?token=abc',
            responseBody: CapturedBody::captured(
                json_encode(['note' => 'the abc report is abc-numbered']),
                contentType: 'application/json',
            ),
        );

        $result = (new Redactor())->redact($exchange);

        expect($result->responseBody->bytes)->toContain('abc report');
    });

    it('does not sweep when redaction is disabled', function (): void {
        $redactor = new Redactor(new RedactionConfig(enabled: false));

        $result = $redactor->redact(exchange(
            uri: 'https://api.example.com/v1?api_key=SUPERSECRETVALUE',
            responseBody: CapturedBody::captured('{"k":"SUPERSECRETVALUE"}', contentType: 'application/json'),
        ));

        expect($result->responseBody->bytes)->toContain('SUPERSECRETVALUE');
    });
});

describe('the collector', function (): void {
    it('ignores values below the minimum length', function (): void {
        $secrets = new KnownSecrets(minLength: 8);
        $secrets->remember('short');

        expect($secrets->isEmpty())->toBeTrue();
    });

    it('stores both raw and url-encoded forms', function (): void {
        $secrets = new KnownSecrets(minLength: 4);
        $secrets->remember('a b c d');

        expect($secrets->count())->toBe(2);
    });

    it('leaves the subject alone when it knows nothing', function (): void {
        expect((new KnownSecrets())->scrub('untouched', '[REDACTED]'))->toBe('untouched');
    });
});
