<?php

declare(strict_types=1);

use Ssx\Wiretap\Cli\Input;
use Ssx\Wiretap\Export\HarExporter;
use Ssx\Wiretap\Headers;
use Ssx\Wiretap\CapturedBody;
use Ssx\Wiretap\Query\ExchangeQuery;
use Ssx\Wiretap\Reader\NdjsonReader;
use Ssx\Wiretap\Sink\NdjsonFileSink;
use Ssx\Wiretap\Timings;

describe('argv parsing', function (): void {
    it('reads the several forms people actually type', function (): void {
        $input = Input::fromArgv(['show', '1', '--host=api.example.com', '--limit', '50', '--curl', '-v']);

        expect($input->argument(0))->toBe('show')
            ->and($input->argument(1))->toBe('1')
            ->and($input->option('host'))->toBe('api.example.com')
            ->and($input->integer('limit', 20))->toBe(50)
            ->and($input->flag('curl'))->toBeTrue()
            ->and($input->flag('v'))->toBeTrue()
            ->and($input->flag('absent'))->toBeFalse();
    });

    it('does not let a bare flag swallow the next option', function (): void {
        // `--failed --host x` must not parse as host of "--host".
        $input = Input::fromArgv(['--failed', '--host', 'api.example.com']);

        expect($input->flag('failed'))->toBeTrue()
            ->and($input->option('host'))->toBe('api.example.com');
    });

    it('falls back to the default for a non-numeric integer option', function (): void {
        expect(Input::fromArgv(['--limit=abc'])->integer('limit', 20))->toBe(20);
    });
});

describe('reading records back', function (): void {
    beforeEach(function (): void {
        $this->dir = sys_get_temp_dir() . '/wiretap-reader-' . bin2hex(random_bytes(6));
        $sink = new NdjsonFileSink($this->dir);

        $sink->writeBatch([
            exchange(uri: 'https://a.example.com/one', status: 200, correlationId: 'c1'),
            exchange(uri: 'https://b.example.com/two', status: 500, correlationId: 'c1'),
            exchange(uri: 'https://a.example.com/three', method: 'GET', status: 404, correlationId: 'c2'),
        ]);

        $this->reader = new NdjsonReader($this->dir);
    });

    afterEach(function (): void {
        foreach (glob($this->dir . '/*') ?: [] as $f) {
            @unlink($f);
        }
        @rmdir($this->dir);
    });

    it('round-trips an exchange through the log file', function (): void {
        $found = iterator_to_array($this->reader->query(new ExchangeQuery(host: 'b.example.com')), false);

        expect($found)->toHaveCount(1)
            ->and($found[0]->uri)->toBe('https://b.example.com/two')
            ->and($found[0]->status)->toBe(500)
            ->and($found[0]->method)->toBe('POST');
    });

    it('filters by host without matching a substring of the url', function (): void {
        $found = iterator_to_array($this->reader->query(new ExchangeQuery(host: 'a.example.com')), false);

        expect($found)->toHaveCount(2);
    });

    it('filters by status class', function (): void {
        $found = iterator_to_array($this->reader->query(new ExchangeQuery(statusClass: '5xx')), false);

        expect($found)->toHaveCount(1)
            ->and($found[0]->status)->toBe(500);
    });

    it('filters to failures only', function (): void {
        $found = iterator_to_array($this->reader->query(new ExchangeQuery(failedOnly: true)), false);

        expect($found)->toHaveCount(2);
    });

    it('filters by correlation id', function (): void {
        $found = iterator_to_array($this->reader->query(new ExchangeQuery(correlationId: 'c1')), false);

        expect($found)->toHaveCount(2);
    });

    it('honours the limit', function (): void {
        expect(iterator_to_array($this->reader->query(new ExchangeQuery(limit: 1)), false))->toHaveCount(1);
    });

    it('skips a line torn by a crash mid-write rather than abandoning the listing', function (): void {
        file_put_contents(
            (new NdjsonFileSink($this->dir))->currentFile(),
            '{"id":"broken","uri":"https://c.exa' . "\n",
            FILE_APPEND,
        );

        // The three good records must still come back.
        expect(iterator_to_array($this->reader->query(new ExchangeQuery(limit: 50)), false))
            ->toHaveCount(3);
    });

    it('resolves a listing position, so `show 1` means the top row', function (): void {
        $first = $this->reader->findByPosition(1, new ExchangeQuery());

        expect($first)->not->toBeNull()
            ->and($first->uri)->toBe('https://a.example.com/three');
    });
});

describe('HAR export', function (): void {
    it('produces a structurally valid HAR 1.2 log', function (): void {
        $har = (new HarExporter())->export([
            exchange(
                uri: 'https://api.example.com/v1/orders?page=2',
                requestHeaders: Headers::fromRaw('Content-Type: application/json'),
                requestBody: CapturedBody::captured('{"a":1}', contentType: 'application/json'),
                responseHeaders: Headers::fromRaw('Content-Type: application/json'),
                responseBody: CapturedBody::captured('{"ok":true}', contentType: 'application/json'),
                timings: new Timings(dns: 10_000, connect: 50_000, tls: 90_000, ttfb: 200_000, total: 250_000),
            ),
        ]);

        $entry = $har['log']['entries'][0];

        expect($har['log']['version'])->toBe('1.2')
            ->and($entry)->toHaveKeys(['startedDateTime', 'time', 'request', 'response', 'cache', 'timings'])
            ->and($entry['request'])->toHaveKeys(['method', 'url', 'httpVersion', 'cookies', 'headers', 'queryString', 'headersSize', 'bodySize'])
            ->and($entry['response'])->toHaveKeys(['status', 'statusText', 'httpVersion', 'cookies', 'headers', 'content', 'redirectURL'])
            ->and($entry['request']['queryString'])->toBe([['name' => 'page', 'value' => '2']])
            ->and($entry['request']['postData']['text'])->toBe('{"a":1}')
            ->and($entry['response']['content']['text'])->toBe('{"ok":true}');
    });

    it('reports unmeasured timing phases as -1 rather than zero', function (): void {
        // Zero would draw a waterfall implying the phase took no time, which
        // is a different claim from not having measured it.
        $har = (new HarExporter())->export([
            exchange(timings: new Timings(total: 100_000)),
        ]);

        $timings = $har['log']['entries'][0]['timings'];

        expect($timings['dns'])->toBe(-1)
            ->and($timings['connect'])->toBe(-1)
            ->and($timings['blocked'])->toBe(-1);
    });

    it('explains an omitted body instead of showing an empty one', function (): void {
        $har = (new HarExporter())->export([
            exchange(responseBody: CapturedBody::omitted(CapturedBody::OMITTED_BINARY, 4096, 'image/png')),
        ]);

        $content = $har['log']['entries'][0]['response']['content'];

        expect($content)->not->toHaveKey('text')
            ->and($content['comment'])->toContain('binary')
            ->and($content['size'])->toBe(4096);
    });

    it('emits parseable json', function (): void {
        $json = (new HarExporter())->toJson([exchange()]);

        expect(json_decode($json, true))->toBeArray()
            ->and(json_last_error())->toBe(JSON_ERROR_NONE);
    });
});
