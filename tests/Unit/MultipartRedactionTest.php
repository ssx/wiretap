<?php

declare(strict_types=1);

use Ssx\Wiretap\CapturedBody;
use Ssx\Wiretap\Headers;
use Ssx\Wiretap\Redaction\RedactionConfig;
use Ssx\Wiretap\Redaction\Redactor;

const MP_TYPE = 'multipart/form-data; boundary=----wiretapTest7MA4YWxk';

/**
 * @param list<array{0: string, 1: string, 2?: string}> $parts name, content, extra header lines
 */
function multipart(array $parts, string $boundary = '----wiretapTest7MA4YWxk'): string
{
    $body = '';

    foreach ($parts as $part) {
        $body .= '--' . $boundary . "\r\n"
            . 'Content-Disposition: form-data; name="' . $part[0] . '"' . ($part[2] ?? '') . "\r\n"
            . "\r\n"
            . $part[1] . "\r\n";
    }

    return $body . '--' . $boundary . "--\r\n";
}

function mpBody(string $bytes, string $type = MP_TYPE): CapturedBody
{
    return CapturedBody::captured($bytes, contentType: $type, sha256: hash('sha256', $bytes));
}

describe('a multipart/form-data body', function (): void {
    it('is captured, not omitted as binary', function (): void {
        $bytes = multipart([['q', 'hello'], ['page', '2']]);

        $result = (new Redactor())->redactBody(mpBody($bytes));

        expect($result->omittedReason)->toBeNull()
            ->and($result->bytes)->toBe($bytes)
            // Untouched, so the digest still describes what is stored.
            ->and($result->sha256)->toBe(hash('sha256', $bytes));
    });

    it('has a body path rule applied by part name, splicing only that part', function (): void {
        $bytes = multipart([['username', 'bob'], ['password', 'hunter2hunter2'], ['user[pin]', '4821']]);
        $redactor = new Redactor(new RedactionConfig(bodyPaths: ['password', 'user.pin']));

        $result = $redactor->redactBody(mpBody($bytes));

        expect($result->bytes)->toBe(multipart([['username', 'bob'], ['password', '[REDACTED]'], ['user[pin]', '[REDACTED]']]))
            ->and($result->sha256)->toBeNull();
    });

    it('teaches the rest of the exchange what a path rule removed', function (): void {
        $redactor = new Redactor(new RedactionConfig(bodyPaths: ['password']));

        $result = $redactor->redact(exchange(
            requestBody: mpBody(multipart([['password', 'ordinary-secret-value']])),
            responseBody: CapturedBody::captured('{"echo":"ordinary-secret-value"}', contentType: 'application/json'),
        ));

        expect((string) $result->responseBody->bytes)->not->toContain('ordinary-secret-value');
    });

    it('has echoed secrets swept from its text parts', function (): void {
        $result = (new Redactor())->redact(exchange(
            requestHeaders: Headers::fromRaw('Authorization: Bearer ordinarysecretvalue'),
            requestBody: mpBody(multipart([['note', 'token was ordinarysecretvalue'], ['q', 'x']])),
        ));

        expect($result->requestBody->bytes)->toBe(multipart([['note', 'token was [REDACTED]'], ['q', 'x']]));
    });

    it('has the detectors run over its text parts', function (): void {
        $result = (new Redactor())->redactBody(mpBody(multipart([['card', '4111 1111 1111 1111'], ['q', 'x']])));

        expect($result->bytes)->toBe(multipart([['card', '[REDACTED]'], ['q', 'x']]));
    });

    it('never stores a file part, keeping what it was instead', function (): void {
        $png = "\x89PNG\r\n\x1a\n" . str_repeat("\x00\xff", 20);
        $bytes = multipart([
            ['caption', 'holiday'],
            ['photo', $png, "; filename=\"me.png\"\r\nContent-Type: image/png"],
        ]);

        $stored = (string) (new Redactor())->redactBody(mpBody($bytes))->bytes;

        expect($stored)->not->toContain("\x89PNG")
            ->and($stored)->toContain('holiday')
            ->and($stored)->toContain('name="photo"; filename="me.png"')
            ->and($stored)->toContain('[file part omitted: name="photo", filename="me.png", type="image/png", size=' . strlen($png) . ']');
    });

    it('treats a part with a binary type as a file even without a filename', function (): void {
        $bytes = multipart([['blob', 'secret-bytes', "\r\nContent-Type: application/octet-stream"]]);

        $stored = (string) (new Redactor())->redactBody(mpBody($bytes))->bytes;

        expect($stored)->not->toContain('secret-bytes')
            ->and($stored)->toContain('[file part omitted: name="blob", filename=null, type="application/octet-stream", size=12]');
    });

    it('treats a file part of a text type as a file too', function (): void {
        $bytes = multipart([['doc', 'password=hunter2', "; filename=\"creds.txt\"\r\nContent-Type: text/plain"]]);

        expect((string) (new Redactor())->redactBody(mpBody($bytes))->bytes)->not->toContain('hunter2');
    });

    it('reads the layout each bridge sends', function (string $boundary, string $partHeaders, string $fileHeaders): void {
        $body = static fn (string $password, string $file): string => "--{$boundary}\r\n"
            . str_replace('{name}', 'password', $partHeaders) . "\r\n\r\n{$password}\r\n"
            . "--{$boundary}\r\n"
            . $fileHeaders . "\r\n\r\n{$file}\r\n"
            . "--{$boundary}--\r\n";
        $redactor = new Redactor(new RedactionConfig(bodyPaths: ['password']));

        $result = $redactor->redactBody(mpBody($body('hunter2hunter2', "\x89PNG\r\n\x1a\nBINARY"), 'multipart/form-data; boundary=' . $boundary));

        expect($result->bytes)->toBe($body('[REDACTED]', '[file part omitted: name="avatar", filename="me.png", type="image/png", size=14]'));
    })->with([
        // Guzzle's MultipartStream.
        'guzzle' => [
            'fce7849ea064a39ba7340ec4ccb2f090a0b90066',
            "Content-Disposition: form-data; name=\"{name}\"\r\nContent-Length: 14",
            "Content-Disposition: form-data; name=\"avatar\"; filename=\"me.png\"\r\nContent-Length: 14\r\nContent-Type: image/png",
        ],
        // Symfony Mime's FormDataPart.
        'symfony' => [
            'aKLW_70J',
            "Content-Type: text/plain; charset=utf-8\r\nContent-Transfer-Encoding: 8bit\r\nContent-Disposition: form-data; name=\"{name}\"",
            "Content-Type: image/png\r\nContent-Transfer-Encoding: 8bit\r\nContent-Disposition: form-data; name=\"avatar\"; filename=\"me.png\"",
        ],
        // wiretap-auto's rebuild of an array CURLOPT_POSTFIELDS (text only;
        // a CURLFile is not rebuilt).
        'curl array postfields' => [
            '------------------------wiretapreconstructed00',
            "Content-Disposition: form-data; name=\"{name}\"",
            "Content-Disposition: form-data; name=\"avatar\"; filename=\"me.png\"\r\nContent-Type: image/png",
        ],
    ]);

    it('is omitted whole when it cannot be read', function (string $bytes, string $type): void {
        $result = (new Redactor())->redactBody(mpBody($bytes, $type));

        expect($result->isPresent())->toBeFalse()
            ->and($result->omittedReason)->toBe(CapturedBody::OMITTED_REDACTED)
            ->and($result->sha256)->toBeNull();
    })->with([
        'no boundary' => [multipart([['q', 'x']]), 'multipart/form-data'],
        'wrong boundary' => [multipart([['q', 'x']]), 'multipart/form-data; boundary=other'],
        'no closing delimiter (truncated)' => [substr(multipart([['q', 'x'], ['password', 'hunter2']]), 0, -40), MP_TYPE],
        'preamble' => ["junk\r\n" . multipart([['q', 'x']]), MP_TYPE],
        'LF line endings' => [str_replace("\r\n", "\n", multipart([['q', 'x']])), MP_TYPE],
        'no name' => [str_replace('; name="q"', '', multipart([['q', 'x']])), MP_TYPE],
        'folded header' => [str_replace("form-data;", "form-data;\r\n ", multipart([['q', 'x']])), MP_TYPE],
        'encoded part' => [multipart([['q', 'aHVudGVyMg==', "\r\nContent-Transfer-Encoding: base64"]]), MP_TYPE],
        'epilogue' => [multipart([['q', 'x']]) . 'trailing', MP_TYPE],
    ]);

    it('is omitted whole when a detector cannot run', function (): void {
        $redactor = new Redactor(new RedactionConfig(custom: ['/ordinary-secret/u']));

        $result = $redactor->redactBody(mpBody(multipart([['note', "ordinary-secret\xff"]])));

        expect($result->isPresent())->toBeFalse()
            ->and($result->omittedReason)->toBe(CapturedBody::OMITTED_REDACTED);
    });

    it('is omitted whole when the safety net still finds a secret', function (): void {
        // A JWT written with a JSON escape inside a text part walks past the
        // detectors on the raw part; the safety net sees it decoded.
        $jwt = 'eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.c2lnbmF0dXJlc2lnbmF0dXJl';
        $part = '{"t":"\\u0065' . substr($jwt, 1) . '"}';

        $result = (new Redactor())->redactBody(mpBody(multipart([['meta', $part, "\r\nContent-Type: application/json"]])));

        expect($result->isPresent())->toBeFalse();
    });
});
