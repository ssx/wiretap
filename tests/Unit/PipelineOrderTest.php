<?php

declare(strict_types=1);

use Ssx\Wiretap\CapturedBody;
use Ssx\Wiretap\Exchange;
use Ssx\Wiretap\Headers;
use Ssx\Wiretap\Query\ExchangeQuery;
use Ssx\Wiretap\Reader\NdjsonReader;
use Ssx\Wiretap\Recorder;
use Ssx\Wiretap\Redaction\RedactionConfig;
use Ssx\Wiretap\Redaction\Redactor;
use Ssx\Wiretap\Sampler;
use Ssx\Wiretap\Sink\NdjsonFileSink;
use Ssx\Wiretap\Timings;

function pipelineExchange(string $uri = 'https://api.example.com/v1'): Exchange
{
    return new Exchange(
        id: bin2hex(random_bytes(8)),
        correlationId: bin2hex(random_bytes(8)),
        transport: 'curl',
        method: 'GET',
        uri: $uri,
        requestHeaders: Headers::empty(),
        requestBody: CapturedBody::none(),
        status: 200,
        reason: 'OK',
        responseHeaders: Headers::empty(),
        responseBody: CapturedBody::none(),
        timings: new Timings(total: 1),
        error: null,
        startedAt: 1.0,
    );
}

describe('pipeline order', function (): void {
    it('matches alwaysHosts against the URI as sent, not as redacted', function (): void {
        // Redaction runs after sampling now. When it ran first, a rule that
        // rewrote any part of the URI could rewrite the host with it, and the
        // host the operator named in alwaysHosts stopped matching itself —
        // so the one exchange they had asked to always keep was the one
        // sampling threw away.
        $recorder = new Recorder(
            redactor: new Redactor(new RedactionConfig(custom: ['/api\.example\.com/'])),
            // Nothing is kept by rate, so only the host rule can save it.
            sampler: new Sampler(rateBasisPoints: 0, alwaysHosts: ['api.example.com']),
        );

        $recorder->record(pipelineExchange());

        expect($recorder->buffered())->toHaveCount(1)
            ->and($recorder->buffered()[0]->uri)->not->toContain('api.example.com');
    });

    it('still drops an exchange that no rule keeps', function (): void {
        $recorder = new Recorder(
            sampler: new Sampler(rateBasisPoints: 0, alwaysKeepFailures: false),
        );

        $recorder->record(pipelineExchange('https://other.example.com/v1'));

        expect($recorder->buffered())->toBeEmpty();
    });
});

describe('reader freshness', function (): void {
    beforeEach(function (): void {
        $this->dir = sys_get_temp_dir() . '/wiretap-reader-' . bin2hex(random_bytes(6));
    });

    afterEach(function (): void {
        if (!is_dir($this->dir)) {
            return;
        }

        array_map('unlink', glob($this->dir . '/*') ?: []);
        rmdir($this->dir);
    });

    it('sees records appended after an earlier read in the same process', function (): void {
        // filesize() is cached per path, so a long-lived reader — a framework
        // bridge UI polling a file a worker appends to — kept seeing the size
        // from its first look and never returned the newest records.
        $sink = new NdjsonFileSink($this->dir);
        $reader = new NdjsonReader($this->dir);

        $sink->write(pipelineExchange('https://first.example.com/'));
        expect(iterator_to_array($reader->query(new ExchangeQuery(limit: 10))))->toHaveCount(1);

        $sink->write(pipelineExchange('https://second.example.com/'));

        expect(iterator_to_array($reader->query(new ExchangeQuery(limit: 10))))->toHaveCount(2);
    });

    it('returns nothing for a non-positive limit', function (): void {
        (new NdjsonFileSink($this->dir))->write(pipelineExchange());

        $reader = new NdjsonReader($this->dir);

        expect(iterator_to_array($reader->query(new ExchangeQuery(limit: 0))))->toBeEmpty()
            ->and(iterator_to_array($reader->query(new ExchangeQuery(limit: -1))))->toBeEmpty();
    });
});
