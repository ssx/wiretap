<?php

declare(strict_types=1);

use Ssx\Wiretap\CapturedBody;
use Ssx\Wiretap\Headers;
use Ssx\Wiretap\Redaction\Patterns;
use Ssx\Wiretap\Redaction\RedactionConfig;
use Ssx\Wiretap\Redaction\Redactor;

describe('the Luhn gate', function (): void {
    it('accepts real card numbers', function (string $pan): void {
        expect(Patterns::passesLuhn($pan))->toBeTrue();
    })->with([
        '4111111111111111',     // Visa
        '5500005555555559',     // Mastercard
        '378282246310005',      // Amex
        '6011111111111117',     // Discover
        '4111 1111 1111 1111',  // spaced
        '4111-1111-1111-1111',  // hyphenated
    ]);

    it('rejects digit strings that merely look like cards', function (string $notPan): void {
        expect(Patterns::passesLuhn($notPan))->toBeFalse();
    })->with([
        '1234567890123456',     // sequential order id
        '1758123456789012',     // millisecond timestamp with digits appended
        '9999999999999999',
        '411111111111111',       // one digit short of the Visa test PAN
    ]);

    it('rejects anything outside 13 to 19 digits', function (): void {
        expect(Patterns::passesLuhn('411111111111'))->toBeFalse()
            ->and(Patterns::passesLuhn('41111111111111111111'))->toBeFalse();
    });
});

describe('url redaction', function (): void {
    it('redacts sensitive query parameters and keeps the rest', function (): void {
        $url = (new Redactor())->redactUrl(
            'https://api.example.com/v1/orders?api_key=SUPERSECRET&page=2&token=abc'
        );

        expect($url)->not->toContain('SUPERSECRET')
            ->and($url)->not->toContain('abc')
            ->and($url)->toContain('page=2');
    });

    it('redacts credentials embedded in userinfo', function (): void {
        $url = (new Redactor())->redactUrl('https://alice:hunter2@api.example.com/v1');

        expect($url)->not->toContain('hunter2')
            ->and($url)->not->toContain('alice')
            ->and($url)->toContain('api.example.com');
    });

    it('leaves a url without a query string alone', function (): void {
        expect((new Redactor())->redactUrl('https://api.example.com/v1/orders'))
            ->toBe('https://api.example.com/v1/orders');
    });
});

describe('header redaction', function (): void {
    it('redacts the default denylist case-insensitively', function (): void {
        $headers = (new Redactor())->redactHeaders(Headers::fromRaw(
            "AUTHORIZATION: Bearer TOPSECRET\r\nx-api-key: kkk\r\nContent-Type: application/json"
        ));

        expect($headers->first('Authorization'))->toBe('[REDACTED]')
            ->and($headers->first('X-Api-Key'))->toBe('[REDACTED]')
            ->and($headers->first('Content-Type'))->toBe('application/json');
    });

    it('removes everything unlisted in allowlist mode', function (): void {
        $redactor = new Redactor(new RedactionConfig(
            headerMode: RedactionConfig::MODE_ALLOW,
            headers: ['content-type'],
        ));

        $headers = $redactor->redactHeaders(Headers::fromRaw(
            "Content-Type: application/json\r\nX-Custom: interesting"
        ));

        expect($headers->first('Content-Type'))->toBe('application/json')
            ->and($headers->first('X-Custom'))->toBe('[REDACTED]');
    });

    it('preserves duplicate headers', function (): void {
        $headers = (new Redactor())->redactHeaders(Headers::fromRaw(
            "Set-Cookie: a=1\r\nSet-Cookie: b=2"
        ));

        expect($headers->get('Set-Cookie'))->toBe(['[REDACTED]', '[REDACTED]']);
    });
});

describe('body redaction', function (): void {
    it('redacts a valid PAN but leaves a same-length order id alone', function (): void {
        $body = CapturedBody::captured(
            json_encode(['order_id' => '1234567890123456', 'pan' => '4111111111111111']),
            contentType: 'application/json',
        );

        $result = (new Redactor())->redactBody($body);

        expect($result->bytes)->toContain('1234567890123456')
            ->and($result->bytes)->not->toContain('4111111111111111');
    });

    it('redacts configured dot paths', function (): void {
        $redactor = new Redactor(new RedactionConfig(bodyPaths: ['card.cvv', 'customer.email']));

        $result = $redactor->redactBody(CapturedBody::captured(
            json_encode([
                'card' => ['cvv' => '123', 'brand' => 'visa'],
                'customer' => ['email' => 'a@b.com', 'name' => 'Alice'],
            ]),
            contentType: 'application/json',
        ));

        $decoded = json_decode((string) $result->bytes, true);

        expect($decoded['card']['cvv'])->toBe('[REDACTED]')
            ->and($decoded['card']['brand'])->toBe('visa')
            ->and($decoded['customer']['email'])->toBe('[REDACTED]')
            ->and($decoded['customer']['name'])->toBe('Alice');
    });

    it('supports wildcard path segments', function (): void {
        $redactor = new Redactor(new RedactionConfig(bodyPaths: ['payments.*.token']));

        $result = $redactor->redactBody(CapturedBody::captured(
            json_encode(['payments' => [
                ['token' => 'tok_1', 'amount' => 100],
                ['token' => 'tok_2', 'amount' => 200],
            ]]),
            contentType: 'application/json',
        ));

        expect($result->bytes)->not->toContain('tok_1')
            ->and($result->bytes)->not->toContain('tok_2')
            ->and($result->bytes)->toContain('100');
    });

    it('omits a binary body, keeping its size and hash', function (): void {
        $result = (new Redactor())->redactBody(CapturedBody::captured(
            "\x89PNG\r\n\x1a\n binary payload",
            size: 4096,
            contentType: 'image/png',
            sha256: 'deadbeef',
        ));

        expect($result->isPresent())->toBeFalse()
            ->and($result->omittedReason)->toBe(CapturedBody::OMITTED_BINARY)
            ->and($result->size)->toBe(4096)
            ->and($result->sha256)->toBe('deadbeef');
    });

    it('drops the whole body when the safety net still finds a secret', function (): void {
        // Structured rules miss it because the key is unexpected, and the
        // JWT detector is switched off, so only the net catches it.
        $redactor = new Redactor(new RedactionConfig(
            patterns: ['pan' => false, 'bearer' => false, 'jwt' => false],
            safetyNet: true,
        ));

        $result = $redactor->redactBody(CapturedBody::captured(
            json_encode(['surprise' => 'eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.abc']),
            contentType: 'application/json',
        ));

        expect($result->isPresent())->toBeFalse()
            ->and($result->omittedReason)->toBe(CapturedBody::OMITTED_REDACTED);
    });

    it('redacts before truncating, so a PAN cannot be split across the boundary', function (): void {
        // The PAN sits past the cap. Truncating first would cut it in half
        // and leave a digit fragment no detector would ever match again.
        $padding = str_repeat('x', 100);
        $payload = json_encode(['pad' => $padding, 'pan' => '4111111111111111']);

        $redactor = new Redactor(new RedactionConfig(maxBodyBytes: 80));
        $result = $redactor->redactBody(CapturedBody::captured($payload, contentType: 'application/json'));

        expect($result->bytes)->not->toContain('4111')
            ->and($result->truncated)->toBeTrue();
    });

    it('does nothing at all when disabled', function (): void {
        $redactor = new Redactor(new RedactionConfig(enabled: false));
        $exchange = exchange(
            uri: 'https://api.example.com/v1?api_key=SECRET',
            requestHeaders: Headers::fromRaw('Authorization: Bearer TOPSECRET'),
        );

        $result = $redactor->redact($exchange);

        expect($result->uri)->toContain('SECRET')
            ->and($result->requestHeaders->first('Authorization'))->toContain('TOPSECRET');
    });

    it('produces a stable hash hint when asked, without storing the secret', function (): void {
        $redactor = new Redactor(new RedactionConfig(hashHint: true, hashSalt: 'pepper'));

        $first = $redactor->redactHeaders(Headers::fromRaw('Authorization: Bearer AAA'))->first('Authorization');
        $again = $redactor->redactHeaders(Headers::fromRaw('Authorization: Bearer AAA'))->first('Authorization');
        $other = $redactor->redactHeaders(Headers::fromRaw('Authorization: Bearer BBB'))->first('Authorization');

        expect($first)->toMatch('/^\[REDACTED:[0-9a-f]{8}\]$/')
            ->and($first)->toBe($again)
            ->and($first)->not->toBe($other)
            ->and($first)->not->toContain('AAA');
    });
});
