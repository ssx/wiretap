<?php

declare(strict_types=1);

use Ssx\Wiretap\CapturedBody;
use Ssx\Wiretap\Exchange;
use Ssx\Wiretap\Headers;
use Ssx\Wiretap\Redaction\Redactor;
use Ssx\Wiretap\Sink\NdjsonFileSink;
use Ssx\Wiretap\Timings;

function fidelityExchange(string $body): Exchange
{
    return new Exchange(
        id: 'x',
        correlationId: 'c',
        transport: 'curl',
        method: 'POST',
        uri: 'https://api.example.com/v1/orders',
        // Makes KnownSecrets non-empty, which is what used to send every
        // body through a decode/re-encode round trip.
        requestHeaders: Headers::fromRaw('Authorization: Bearer ordinarysecretvalue'),
        requestBody: CapturedBody::none(),
        status: 200,
        reason: 'OK',
        responseHeaders: Headers::empty(),
        responseBody: CapturedBody::captured($body, contentType: 'application/json'),
        timings: new Timings(total: 1),
        error: null,
        startedAt: 1.0,
    );
}

describe('record fidelity', function (): void {
    it('returns a body it did not change byte for byte', function (): void {
        $body = '{"id":12345678901234567890,"meta":{},"amount":10.0,"ok":true}';

        $result = (new Redactor())->redact(fidelityExchange($body));

        expect($result->responseBody->bytes)->toBe($body);
    });

    it('keeps oversized integers, empty objects and zero fractions when it does change one', function (): void {
        // Re-encoding is unavoidable once a value has been swept, but it must
        // not rewrite the values it was not asked to touch. This body used to
        // come back as {"id":1.2345678901234567e+19,"meta":[],"amount":10,...}
        // — a different order id, an object turned into an array, and a money
        // value that lost its scale.
        $body = '{"id":12345678901234567890,"meta":{},"amount":10.0,"echo":"ordinarysecretvalue"}';

        $result = (new Redactor())->redact(fidelityExchange($body));
        $bytes = $result->responseBody->bytes;

        expect($bytes)->toContain('"id":12345678901234567890')
            ->and($bytes)->toContain('"meta":{}')
            ->and($bytes)->toContain('"amount":10.0')
            ->and($bytes)->not->toContain('ordinarysecretvalue')
            ->and(json_decode((string) $bytes, true))->not->toBeNull();
    });

    it('does not confuse a numeric string with an oversized integer', function (): void {
        $body = '{"n":99999999999999999999,"s":"99999999999999999999","echo":"ordinarysecretvalue"}';

        $bytes = (string) (new Redactor())->redact(fidelityExchange($body))->responseBody->bytes;

        expect($bytes)->toContain('"n":99999999999999999999')
            ->and($bytes)->toContain('"s":"99999999999999999999"');
    });

    it('preserves oversized integers nested in arrays and objects', function (): void {
        $body = '{"o":{"deep":[1,99999999999999999999]},"echo":"ordinarysecretvalue"}';

        $bytes = (string) (new Redactor())->redact(fidelityExchange($body))->responseBody->bytes;

        expect($bytes)->toContain('[1,99999999999999999999]');
    });
});

describe('log file exposure', function (): void {
    beforeEach(function (): void {
        $this->dir = sys_get_temp_dir() . '/wiretap-test-' . bin2hex(random_bytes(6));
    });

    afterEach(function (): void {
        if (!is_dir($this->dir)) {
            return;
        }

        array_map('unlink', glob($this->dir . '/*') ?: []);
        rmdir($this->dir);
    });

    it('creates the log directory and files readable only by their owner', function (): void {
        (new NdjsonFileSink($this->dir))->write(fidelityExchange('{}'));

        $file = glob($this->dir . '/*.ndjson')[0] ?? null;

        expect($file)->not->toBeNull()
            ->and(fileperms($this->dir) & 0o077)->toBe(0)
            ->and(fileperms((string) $file) & 0o077)->toBe(0);
    });

    it('refuses to append through a symlink', function (): void {
        mkdir($this->dir, 0o700, true);

        $victim = $this->dir . '/victim';
        file_put_contents($victim, "ORIGINAL\n");

        $sink = new NdjsonFileSink($this->dir);
        symlink($victim, $sink->currentFile());

        $sink->write(fidelityExchange('{}'));

        expect(file_get_contents($victim))->toBe("ORIGINAL\n");
    });

    it('refuses to write into a directory owned by another user', function (): void {
        if (!function_exists('posix_geteuid') || posix_geteuid() === 0) {
            $this->markTestSkipped('needs ext-posix and a non-root user');
        }

        $sink = new NdjsonFileSink('/tmp');
        $before = glob('/tmp/wiretap-*.ndjson') ?: [];

        $sink->write(fidelityExchange('{}'));

        expect(glob('/tmp/wiretap-*.ndjson') ?: [])->toBe($before);
    });

    it('resolves the same default directory for the writer and the CLI reader', function (): void {
        // These used to be two separate expressions. Moving the recorder to a
        // per-user directory without moving the reader would have left
        // `wiretap list` reporting no traffic on a working capture.
        $method = new ReflectionMethod(Ssx\Wiretap\Wiretap::class, 'defaultSink');
        $method->setAccessible(true);

        $sink = $method->invoke(null);
        $property = new ReflectionProperty($sink, 'directory');
        $property->setAccessible(true);

        expect($property->getValue($sink))->toBe(Ssx\Wiretap\Wiretap::defaultLogPath());
    });

    it('defaults to a per-user directory rather than a shared one', function (): void {
        $method = new ReflectionMethod(Ssx\Wiretap\Wiretap::class, 'defaultSink');
        $method->setAccessible(true);

        $sink = $method->invoke(null);
        $property = new ReflectionProperty($sink, 'directory');
        $property->setAccessible(true);

        expect($property->getValue($sink))->not->toBe(sys_get_temp_dir() . '/wiretap');
    });
});
