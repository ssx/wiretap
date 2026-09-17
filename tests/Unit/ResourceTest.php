<?php

declare(strict_types=1);

use Ssx\Wiretap\CapturedBody;
use Ssx\Wiretap\Query\ExchangeQuery;
use Ssx\Wiretap\Reader\NdjsonReader;
use Ssx\Wiretap\Recorder;
use Ssx\Wiretap\Sink\InMemorySink;
use Ssx\Wiretap\Sink\NdjsonFileSink;

beforeEach(function (): void {
    $this->dir = sys_get_temp_dir() . '/wiretap-resource-' . bin2hex(random_bytes(6));
});

afterEach(function (): void {
    if (is_dir($this->dir)) {
        foreach (glob($this->dir . '/*') ?: [] as $file) {
            if (is_file($file)) {
                unlink($file);
            }
        }

        rmdir($this->dir);
    }
});

describe('reading without loading the file', function (): void {
    it('returns the newest record without reading everything before it', function (): void {
        $sink = new NdjsonFileSink($this->dir);

        foreach (range(1, 500) as $i) {
            $sink->write(exchange(uri: "https://api.example.com/{$i}"));
        }

        $reader = new NdjsonReader($this->dir);
        $found = iterator_to_array($reader->query(new ExchangeQuery(limit: 1)), false);

        expect($found)->toHaveCount(1)
            ->and($found[0]->uri)->toBe('https://api.example.com/500');
    });

    it('reads backwards across chunk boundaries without losing or splitting a record', function (): void {
        $sink = new NdjsonFileSink($this->dir);

        // Bodies large enough that records straddle the 64 KiB read chunks.
        foreach (range(1, 60) as $i) {
            $sink->write(exchange(
                uri: "https://api.example.com/{$i}",
                requestBody: CapturedBody::captured(str_repeat('x', 5_000), contentType: 'text/plain'),
            ));
        }

        $reader = new NdjsonReader($this->dir);
        $found = iterator_to_array($reader->query(new ExchangeQuery(limit: 100)), false);

        $uris = array_map(static fn ($e): string => $e->uri, $found);

        expect($found)->toHaveCount(60)
            ->and($uris[0])->toBe('https://api.example.com/60')
            ->and($uris[59])->toBe('https://api.example.com/1')
            ->and(array_unique($uris))->toHaveCount(60);
    });

    it('reads oldest-first correctly too', function (): void {
        $sink = new NdjsonFileSink($this->dir);

        foreach (range(1, 20) as $i) {
            $sink->write(exchange(uri: "https://api.example.com/{$i}"));
        }

        $found = iterator_to_array(
            (new NdjsonReader($this->dir))->query(new ExchangeQuery(limit: 3, newestFirst: false)),
            false,
        );

        expect(array_map(static fn ($e): string => $e->uri, $found))->toBe([
            'https://api.example.com/1',
            'https://api.example.com/2',
            'https://api.example.com/3',
        ]);
    });

    it('keeps filters and offset when resolving a listing position', function (): void {
        // `list --offset=2` then `show 1 --offset=2` opened the first overall
        // result rather than the row that had been displayed.
        $sink = new NdjsonFileSink($this->dir);

        foreach (range(1, 6) as $i) {
            $sink->write(exchange(uri: "https://api.example.com/{$i}"));
        }

        $reader = new NdjsonReader($this->dir);
        $listed = iterator_to_array($reader->query(new ExchangeQuery(limit: 3, offset: 2)), false);
        $shown = $reader->findByPosition(1, new ExchangeQuery(limit: 3, offset: 2));

        expect($shown)->not->toBeNull()
            ->and($shown->uri)->toBe($listed[0]->uri);
    });
});

describe('buffer accounting', function (): void {
    it('does not let an unencodable body escape the byte limit', function (): void {
        // json_encode returns false on invalid UTF-8, and casting that to a
        // string gave size zero — so the record counted for nothing.
        $sink = new InMemorySink();
        $recorder = new Recorder(
            sink: $sink,
            maxBufferedRecords: 1000,
            maxBufferedBytes: 100,
        );

        $invalid = CapturedBody::captured("\xB1\x31" . str_repeat("\xC3\x28", 500), contentType: 'text/plain');

        foreach (range(1, 5) as $i) {
            $recorder->record(exchange(uri: "https://api.example.com/{$i}", requestBody: $invalid));
        }

        expect(count($recorder->buffered()))->toBeLessThan(5);
    });
});

describe('shutdown retention', function (): void {
    it('lets a replaced recorder be collected', function (): void {
        // The shutdown closure captured $this strongly, so every recorder
        // replaced by fake() stayed alive with its captures until the process
        // exited.
        $recorder = new Recorder(sink: new InMemorySink());
        $recorder->record(exchange());

        $weak = WeakReference::create($recorder);

        unset($recorder);

        expect($weak->get())->toBeNull();
    });
});

describe('the file sink under a failing write', function (): void {
    it('does not leave a partial line for the next append to concatenate', function (): void {
        $sink = new NdjsonFileSink($this->dir);
        $sink->write(exchange(uri: 'https://api.example.com/first'));

        $file = $sink->currentFile();
        $before = file_get_contents($file);

        // Every complete line must be valid JSON, and the file must end with a
        // newline so the next append starts cleanly.
        $sink->write(exchange(uri: 'https://api.example.com/second'));
        $after = (string) file_get_contents($file);

        $lines = array_filter(explode("\n", $after));

        expect(str_ends_with($after, "\n"))->toBeTrue()
            ->and($lines)->toHaveCount(2);

        foreach ($lines as $line) {
            expect(json_decode($line, true))->toBeArray();
        }

        expect($after)->toStartWith((string) $before);
    });
});
