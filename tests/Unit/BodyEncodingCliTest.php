<?php

declare(strict_types=1);

use Ssx\Wiretap\CapturedBody;
use Ssx\Wiretap\Cli\Application;
use Ssx\Wiretap\Cli\Command\ExportCommand;
use Ssx\Wiretap\Cli\Command\PruneCommand;
use Ssx\Wiretap\Cli\Command\ShowCommand;
use Ssx\Wiretap\Cli\Input;
use Ssx\Wiretap\Cli\Output;
use Ssx\Wiretap\Exchange;
use Ssx\Wiretap\Export\HarExporter;
use Ssx\Wiretap\Reader\NdjsonReader;
use Ssx\Wiretap\Redaction\Redactor;
use Ssx\Wiretap\Sink\NdjsonFileSink;

beforeEach(function (): void {
    $this->dir = sys_get_temp_dir() . '/wiretap-encoding-' . bin2hex(random_bytes(6));
});

afterEach(function (): void {
    foreach (glob($this->dir . '/*') ?: [] as $file) {
        @unlink($file);
    }

    if (is_dir($this->dir)) {
        rmdir($this->dir);
    }
});

/**
 * @param class-string $command
 * @param list<string> $argv
 *
 * @return array{int, string}
 */
function runEncodingCommand(string $command, string $dir, array $argv): array
{
    $stream = fopen('php://memory', 'w+b');
    assert(is_resource($stream));

    $code = (new $command(new NdjsonReader($dir), new Output($stream, decorated: false), $dir))->handle(Input::fromArgv($argv));

    rewind($stream);

    return [$code, (string) stream_get_contents($stream)];
}

function latin1Exchange(string $body, ?string $sha = null, bool $truncated = false, float $startedAt = 1_758_000_000.0): Exchange
{
    return new Exchange(
        id: 'latin1',
        correlationId: 'c',
        transport: Exchange::TRANSPORT_CURL,
        method: 'POST',
        uri: 'https://api.example.com/v1/people',
        requestHeaders: \Ssx\Wiretap\Headers::empty(),
        requestBody: CapturedBody::captured($body, contentType: 'text/plain; charset=iso-8859-1'),
        status: 200,
        reason: 'OK',
        responseHeaders: \Ssx\Wiretap\Headers::empty(),
        responseBody: CapturedBody::captured($body, contentType: 'text/xml; charset=iso-8859-1', truncated: $truncated, sha256: $sha),
        timings: new \Ssx\Wiretap\Timings(total: 1),
        error: null,
        startedAt: $startedAt,
    );
}

describe('a body that is not UTF-8', function (): void {
    it('is stored losslessly beside the digest that describes it', function (): void {
        $latin = "<name>Jos\xE9 M\xFCller</name>";
        $sha = hash('sha256', $latin);

        (new NdjsonFileSink($this->dir))->write((new Redactor())->redact(latin1Exchange($latin, $sha)));

        $line = json_decode(trim((string) file_get_contents((string) glob($this->dir . '/*.ndjson')[0])), true);
        $stored = $line['response']['body'];

        expect($stored['encoding'])->toBe('base64')
            ->and(base64_decode($stored['bytes'], true))->toBe($latin)
            ->and($stored['sha256'])->toBe($sha);

        $read = (new NdjsonReader($this->dir))->find('latin1');

        expect($read?->responseBody->bytes)->toBe($latin)
            ->and(hash('sha256', (string) $read?->responseBody->bytes))->toBe($read?->responseBody->sha256);
    });

    it('leaves a UTF-8 body as readable text', function (): void {
        $body = CapturedBody::captured('{"name":"José"}', contentType: 'application/json');

        expect($body->jsonSerialize())->toHaveKey('bytes', '{"name":"José"}')
            ->and($body->jsonSerialize())->not->toHaveKey('encoding');
    });

    it('keeps a truncated UTF-8 prefix as text when only its last character was cut', function (): void {
        // A prefix cut inside a multibyte character is not valid UTF-8, but
        // it is still text; dropping the partial character keeps it readable.
        $body = CapturedBody::captured("caf\xC3", size: 100, contentType: 'text/plain', truncated: true);

        expect($body->jsonSerialize())->toHaveKey('bytes', 'caf')
            ->and($body->jsonSerialize())->not->toHaveKey('encoding');
    });

    it('is exported to HAR with the base64 encoding HAR defines', function (): void {
        $latin = "Jos\xE9";
        $har = (new HarExporter())->export([latin1Exchange($latin)]);
        $entry = $har['log']['entries'][0];

        expect($entry['response']['content']['encoding'])->toBe('base64')
            ->and(base64_decode($entry['response']['content']['text'], true))->toBe($latin)
            ->and(base64_decode($entry['request']['postData']['text'], true))->toBe($latin)
            ->and($entry['request']['postData']['comment'])->toContain('base64');
    });

    it('is shown with its bytes escaped and marked as not UTF-8', function (): void {
        (new NdjsonFileSink($this->dir))->write(latin1Exchange("Jos\xE9"));

        [, $shown] = runEncodingCommand(ShowCommand::class, $this->dir, ['1']);

        expect($shown)->toContain('Jos\xe9')
            ->and($shown)->toContain('not valid UTF-8');
    });

    it('replays with its exact bytes from show --curl', function (): void {
        (new NdjsonFileSink($this->dir))->write(latin1Exchange("Jos\xE9"));

        [, $curl] = runEncodingCommand(ShowCommand::class, $this->dir, ['1', '--curl']);

        expect($curl)->toContain(base64_encode("Jos\xE9"))
            ->and($curl)->toContain('--data-binary @-');
    });
});

describe('time windows', function (): void {
    it('honours --until on export', function (): void {
        $sink = new NdjsonFileSink($this->dir);
        $sink->write(exchange(uri: 'https://api.example.com/old'));
        $sink->write(new Exchange(
            id: 'recent', correlationId: 'c', transport: Exchange::TRANSPORT_CURL, method: 'GET',
            uri: 'https://api.example.com/recent',
            requestHeaders: \Ssx\Wiretap\Headers::empty(), requestBody: CapturedBody::none(),
            status: 200, reason: 'OK', responseHeaders: \Ssx\Wiretap\Headers::empty(),
            responseBody: CapturedBody::none(), timings: new \Ssx\Wiretap\Timings(total: 1),
            error: null, startedAt: microtime(true),
        ));

        [$code, $har] = runEncodingCommand(ExportCommand::class, $this->dir, ['--until=1h']);

        expect($code)->toBe(0)
            ->and($har)->toContain('https://api.example.com/old')
            ->and($har)->not->toContain('https://api.example.com/recent');
    });

    it('rejects a window it cannot read rather than exporting everything', function (string $option): void {
        (new NdjsonFileSink($this->dir))->write(exchange());

        $stream = fopen('php://memory', 'w+b');
        assert(is_resource($stream));
        $code = (new Application(new Output($stream, decorated: false)))
            ->run(['wiretap', 'export', '--path=' . $this->dir, $option]);
        rewind($stream);

        expect($code)->toBe(1)
            ->and((string) stream_get_contents($stream))->not->toContain('"entries"');
    })->with([['--until=yesterday'], ['--since=last-week']]);

    it('rejects prune --older-than without a unit', function (): void {
        $sink = new NdjsonFileSink($this->dir);
        $sink->write(exchange());

        [$code, $out] = runEncodingCommand(PruneCommand::class, $this->dir, ['--older-than=7']);

        expect($code)->toBe(1)
            ->and($out)->toContain('7d')
            ->and(glob($this->dir . '/*.ndjson'))->not->toBe([]);
    });
});
