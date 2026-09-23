<?php

declare(strict_types=1);

use Ssx\Wiretap\CapturedBody;
use Ssx\Wiretap\Headers;
use Ssx\Wiretap\Redaction\RedactionConfig;
use Ssx\Wiretap\Redaction\Redactor;
use Ssx\Wiretap\TransferError;

describe('request cookies', function (): void {
    it('learns every cookie in a request Cookie header, not just the first', function (): void {
        // Cookie is a list of pairs; Set-Cookie is one pair plus attributes.
        // Parsing the first like the second learned `theme` and nothing
        // after it, so the session value was stored when the API echoed it.
        $out = (new Redactor())->redact(exchange(
            requestHeaders: Headers::fromPairs([['Cookie', 'theme=light; session=ordinary-secret-value; csrf=another-secret-value']]),
            responseBody: CapturedBody::captured('{"echo":"ordinary-secret-value","csrf":"another-secret-value"}', contentType: 'application/json'),
        ));

        expect($out->responseBody->bytes)->not->toContain('ordinary-secret-value')
            ->and($out->responseBody->bytes)->not->toContain('another-secret-value');
    });

    it('still ignores Set-Cookie attributes', function (): void {
        $out = (new Redactor())->redact(exchange(
            uri: 'https://api.example.com/login',
            responseHeaders: Headers::fromPairs([['Set-Cookie', 'sid=abcdefgh12345; Domain=api.example.com; Path=/account-settings']]),
            responseBody: CapturedBody::captured('{"next":"/account-settings","sid":"abcdefgh12345"}', contentType: 'application/json'),
        ));

        expect($out->uri)->toBe('https://api.example.com/login')
            ->and($out->responseBody->bytes)->toContain('/account-settings')
            ->and($out->responseBody->bytes)->not->toContain('abcdefgh12345');
    });
});

describe('body paths in form-encoded bodies', function (): void {
    it('learns a form field a body-path rule removes, so its echo is removed too', function (): void {
        $out = (new Redactor(new RedactionConfig(bodyPaths: ['password'])))->redact(exchange(
            requestBody: CapturedBody::captured('username=bob&password=Hunter2Hunter2', contentType: 'application/x-www-form-urlencoded'),
            responseBody: CapturedBody::captured('{"echo":"Hunter2Hunter2","note":"pw was Hunter2Hunter2"}', contentType: 'application/json'),
        ));

        expect($out->requestBody->bytes)->not->toContain('Hunter2Hunter2')
            ->and($out->responseBody->bytes)->not->toContain('Hunter2Hunter2');
    });

    it('learns nested form fields by their dot path', function (): void {
        $out = (new Redactor(new RedactionConfig(bodyPaths: ['user.password'])))->redact(exchange(
            requestBody: CapturedBody::captured('user%5Bname%5D=bob&user%5Bpassword%5D=Hunter2Hunter2', contentType: 'application/x-www-form-urlencoded'),
            responseBody: CapturedBody::captured('{"echo":"Hunter2Hunter2"}', contentType: 'application/json'),
        ));

        expect($out->responseBody->bytes)->toBe('{"echo":"[REDACTED]"}');
    });
});

describe('a detector that cannot run', function (): void {
    it('drops a non-body field rather than keeping it unexamined', function (): void {
        // A /u custom pattern fails on invalid UTF-8. Bodies were dropped;
        // headers, the error message, the reason and tags kept the value the
        // pattern exists to remove.
        $redactor = new Redactor(new RedactionConfig(custom: ['/acct-[0-9]{6,}/u']));

        $out = $redactor->redact(exchange(
            responseHeaders: Headers::fromPairs([['X-Debug', "acct-12345678 \xff"]]),
            error: new TransferError(7, "failed for acct-12345678 \xff"),
        )->withReason("OK acct-12345678 \xff")->withTags(["acct-12345678 \xff"])
            ->withContext(['route' => "/a/acct-12345678/\xff"]));

        $json = (string) json_encode($out, JSON_INVALID_UTF8_SUBSTITUTE);

        expect($json)->not->toContain('12345678');
    });

    it('drops the path and query of a uri it could not examine, keeping the host', function (): void {
        $redactor = new Redactor(new RedactionConfig(custom: ['/acct-[0-9]{6,}/u']));

        $out = $redactor->redact(exchange(uri: "https://api.example.com/v1/acct-12345678/\xff"));

        expect($out->uri)->not->toContain('12345678')
            ->and($out->uri)->toStartWith('https://api.example.com/');
    });

    it('fails closed when the card detector itself hits a PCRE limit', function (): void {
        $backtrack = ini_get('pcre.backtrack_limit');
        $jit = ini_get('pcre.jit');
        ini_set('pcre.backtrack_limit', '1');
        ini_set('pcre.jit', '0');

        try {
            $out = (new Redactor())->redact(exchange(
                responseHeaders: Headers::fromPairs([['X-Card', '4111 1111 1111 1111']]),
                responseBody: CapturedBody::captured('{"card":"4111 1111 1111 1111"}', contentType: 'application/json'),
            ));
        } finally {
            ini_set('pcre.backtrack_limit', (string) $backtrack);
            ini_set('pcre.jit', (string) $jit);
        }

        expect($out->responseHeaders->first('X-Card'))->not->toContain('4111')
            ->and((string) $out->responseBody->bytes)->not->toContain('4111');
    });
});

describe('detectors see decoded uri values', function (): void {
    it('finds a card number whose spaces were encoded', function (string $uri): void {
        $out = (new Redactor())->redact(exchange(uri: $uri));

        expect($out->uri)->not->toContain('4111')
            ->and($out->uri)->toStartWith('https://example.com/');
    })->with([
        'plus in query' => 'https://example.com/?ref=4111+1111+1111+1111',
        'percent-20 in query' => 'https://example.com/?ref=4111%201111%201111%201111',
        'percent-20 in path' => 'https://example.com/cards/4111%201111%201111%201111/charge',
    ]);

    it('leaves an ordinary query exactly as it was', function (): void {
        $uri = 'https://example.com/search/a+b?page=2&sort=name';

        expect((new Redactor())->redact(exchange(uri: $uri))->uri)->toBe($uri);
    });
});

describe('urls parse_url cannot read', function (): void {
    it('still removes a named parameter however its name is spelled', function (string $uri): void {
        // A port above 65535 makes parse_url fail and the fallback matched
        // the literal name only.
        $out = (new Redactor())->redact(exchange(uri: $uri));

        expect($out->uri)->not->toContain('abcdefgh12345')
            ->and($out->uri)->toStartWith('https://api.example.com:99999/v1?');
    })->with([
        'https://api.example.com:99999/v1?%74oken=abcdefgh12345',
        'https://api.example.com:99999/v1?token[]=abcdefgh12345',
        'https://api.example.com:99999/v1?token%5B0%5D=abcdefgh12345',
        'https://api.example.com:99999/v1?access%5Ftoken=abcdefgh12345',
        'https://api.example.com:99999/v1?x=1;token=abcdefgh12345',
    ]);
});

describe('a capture-layer truncated body', function (): void {
    it('does not keep the digest of bytes it no longer stores', function (): void {
        // The digest described the whole body beside a stored prefix. With
        // a six-digit tail, the tail was recovered from it by brute force in
        // a fraction of a second.
        $full = '{"user":"bob","status":"active","otp":"482193"}';
        $prefix = substr($full, 0, 36);

        $out = (new Redactor())->redact(exchange(responseBody: CapturedBody::captured(
            $prefix,
            size: strlen($full),
            contentType: 'application/json',
            truncated: true,
            sha256: hash('sha256', $full),
        )));

        expect($out->responseBody->bytes)->toBe($prefix)
            ->and($out->responseBody->sha256)->toBeNull();
    });

    it('keeps a keyed digest when a salt is configured', function (): void {
        $full = '{"otp":"482193"}';

        $out = (new Redactor(new RedactionConfig(hashSalt: 'pepper')))->redact(exchange(responseBody: CapturedBody::captured(
            substr($full, 0, 8),
            size: strlen($full),
            contentType: 'application/json',
            truncated: true,
            sha256: hash('sha256', $full),
        )));

        expect($out->responseBody->sha256)->toBe(hash_hmac('sha256', hash('sha256', $full), 'pepper'));
    });

    it('still keeps the digest of an untruncated, unchanged body', function (): void {
        $body = '{"ok":true}';

        $out = (new Redactor())->redact(exchange(responseBody: CapturedBody::captured($body, contentType: 'application/json', sha256: hash('sha256', $body))));

        expect($out->responseBody->sha256)->toBe(hash('sha256', $body));
    });
});

describe('named query parameters outside the uri', function (): void {
    it('removes them from any header carrying a url', function (): void {
        $out = (new Redactor())->redact(exchange(
            uri: 'https://api.example.com/items',
            responseHeaders: Headers::fromPairs([
                ['Link', '<https://api.example.com/items?page=2&access_token=EAAGm0PX4ZCpsBAKZ>; rel="next"'],
                ['X-Original-Url', 'https://api.example.com/items?api_key=K3y_SUPER_S3CRET_VALUE'],
                ['X-Short', 'https://api.example.com/items?page=2&key=abc12'],
            ]),
        ));

        expect($out->responseHeaders->first('Link'))->not->toContain('EAAGm0PX4ZCpsBAKZ')
            ->and($out->responseHeaders->first('Link'))->toContain('page=2')
            ->and($out->responseHeaders->first('Link'))->toEndWith('>; rel="next"')
            ->and($out->responseHeaders->first('X-Original-Url'))->not->toContain('K3y_SUPER_S3CRET_VALUE')
            ->and($out->responseHeaders->first('X-Short'))->not->toContain('abc12');
    });

    it('removes them from urls inside a body, escaped or not', function (): void {
        $out = (new Redactor())->redact(exchange(
            responseBody: CapturedBody::captured(
                '{"next":"https://api.example.com/items?page=2&access_token=EAAGm0PX4ZCpsBAKZ","prev":"https:\/\/api.example.com\/items?page=1&token=tok_escaped_12345"}',
                contentType: 'application/json',
            ),
        ));

        expect($out->responseBody->bytes)->not->toContain('EAAGm0PX4ZCpsBAKZ')
            ->and($out->responseBody->bytes)->not->toContain('tok_escaped_12345')
            ->and(json_decode((string) $out->responseBody->bytes, true))->toBeArray();
    });

    it('leaves a url with nothing sensitive in it untouched', function (): void {
        $body = '{"next":"https://api.example.com/items?page=2&q=a+b"}';

        $out = (new Redactor())->redact(exchange(
            responseHeaders: Headers::fromPairs([['Link', '<https://api.example.com/items?page=2&q=a+b>; rel="next"']]),
            responseBody: CapturedBody::captured($body, contentType: 'application/json'),
        ));

        expect($out->responseBody->bytes)->toBe($body)
            ->and($out->responseHeaders->first('Link'))->toBe('<https://api.example.com/items?page=2&q=a+b>; rel="next"');
    });
});

describe('context values that are not strings', function (): void {
    it('redacts strings nested inside array context values', function (): void {
        // Guzzle records each redirect hop under context.redirected_to as a
        // list. Only top-level strings were redacted, so a hop's token was
        // stored as it was sent.
        $out = (new Redactor())->redact(exchange()->withContext([
            'redirected_to' => [
                'https://api.example.com/cb?token=tok_live_ABCDEFGH12345',
                ['nested' => 'https://api.example.com/cb?access_token=EAAGm0PX4ZCpsBAKZ'],
            ],
            'attempts' => 2,
        ]));

        $json = (string) json_encode($out->context);

        expect($json)->not->toContain('tok_live_ABCDEFGH12345')
            ->and($json)->not->toContain('EAAGm0PX4ZCpsBAKZ')
            ->and($out->context['attempts'])->toBe(2);
    });

    it('learns what it removes from context, so a body echo is removed too', function (): void {
        $out = (new Redactor())->redact(exchange(
            responseBody: CapturedBody::captured('{"echo":"tok_live_ABCDEFGH12345"}', contentType: 'application/json'),
        )->withContext(['redirected_to' => ['https://api.example.com/cb?token=tok_live_ABCDEFGH12345']]));

        expect($out->responseBody->bytes)->not->toContain('tok_live_ABCDEFGH12345');
    });
});
