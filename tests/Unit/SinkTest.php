<?php

declare(strict_types=1);

use Ssx\Wiretap\Contract\ExchangeSink;
use Ssx\Wiretap\Exchange;
use Ssx\Wiretap\Headers;
use Ssx\Wiretap\Sink\InMemorySink;
use Ssx\Wiretap\Sink\MultiSink;
use Ssx\Wiretap\Sink\NdjsonFileSink;

beforeEach(function (): void {
    $this->dir = sys_get_temp_dir() . '/wiretap-test-' . bin2hex(random_bytes(6));
});

afterEach(function (): void {
    if (is_dir($this->dir)) {
        foreach (glob($this->dir . '/*') ?: [] as $file) {
            @unlink($file);
        }
        @rmdir($this->dir);
    }
});

describe('the ndjson sink', function (): void {
    it('writes one json object per line', function (): void {
        $sink = new NdjsonFileSink($this->dir);

        $sink->write(exchange(uri: 'https://api.example.com/1'));
        $sink->write(exchange(uri: 'https://api.example.com/2'));

        $lines = file($sink->currentFile(), FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);

        expect($lines)->toHaveCount(2)
            ->and(json_decode((string) $lines[0], true))->toHaveKey('uri')
            ->and(json_decode((string) $lines[1], true)['uri'])->toBe('https://api.example.com/2');
    });

    it('round-trips headers with duplicates intact', function (): void {
        $sink = new NdjsonFileSink($this->dir);

        $sink->write(exchange(responseHeaders: Headers::fromRaw("Set-Cookie: a=1\r\nSet-Cookie: b=2")));

        $decoded = json_decode((string) file($sink->currentFile())[0], true);

        expect($decoded['response']['headers'])->toBe([['Set-Cookie', 'a=1'], ['Set-Cookie', 'b=2']]);
    });

    it('creates the directory when it does not exist', function (): void {
        expect(is_dir($this->dir))->toBeFalse();

        (new NdjsonFileSink($this->dir))->write(exchange());

        expect(is_dir($this->dir))->toBeTrue();
    });

    it('does not throw when the directory cannot be written', function (): void {
        $sink = new NdjsonFileSink('/proc/nonexistent/wiretap');

        expect(fn () => $sink->write(exchange()))->not->toThrow(Throwable::class);
    });

    it('writes a batch in a single append', function (): void {
        $sink = new NdjsonFileSink($this->dir);

        $sink->writeBatch([exchange(), exchange(), exchange()]);

        expect(file($sink->currentFile(), FILE_SKIP_EMPTY_LINES))->toHaveCount(3);
    });
});

describe('the multi sink', function (): void {
    it('writes to every sink', function (): void {
        $a = new InMemorySink();
        $b = new InMemorySink();

        (new MultiSink($a, $b))->write(exchange());

        expect($a->all())->toHaveCount(1)
            ->and($b->all())->toHaveCount(1);
    });

    it('keeps going when one sink fails', function (): void {
        $working = new InMemorySink();

        $broken = new class implements ExchangeSink {
            public function write(Exchange $exchange): void
            {
                throw new RuntimeException('nope');
            }

            public function writeBatch(iterable $exchanges): void
            {
                throw new RuntimeException('nope');
            }
        };

        (new MultiSink($broken, $working))->write(exchange());

        expect($working->all())->toHaveCount(1);
    });
});

describe('the in-memory sink', function (): void {
    it('is bounded and counts what it drops', function (): void {
        $sink = new InMemorySink(limit: 2);

        $sink->writeBatch([exchange(), exchange(), exchange(), exchange()]);

        expect($sink->all())->toHaveCount(2)
            ->and($sink->dropped())->toBe(2);
    });
});
