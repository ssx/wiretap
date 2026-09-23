<?php

declare(strict_types=1);

use Ssx\Wiretap\CapturedBody;
use Ssx\Wiretap\Cli\Command\ShowCommand;
use Ssx\Wiretap\Cli\Input;
use Ssx\Wiretap\Cli\Output;
use Ssx\Wiretap\Headers;
use Ssx\Wiretap\Reader\NdjsonReader;
use Ssx\Wiretap\Redaction\RedactionConfig;
use Ssx\Wiretap\Redaction\Redactor;
use Ssx\Wiretap\Sink\NdjsonFileSink;

function pathRedactor(): Redactor
{
    return new Redactor(new RedactionConfig(bodyPaths: ['password', 'user.pin']));
}

describe('body path rules that match nothing', function (): void {
    it('store a JSON body byte for byte and keep its digest', function (): void {
        $body = '{"id":12345678901234567890,"meta":{},"amount":10.0,"path":"a/b"}';
        $sha = hash('sha256', $body);

        $result = pathRedactor()->redactBody(CapturedBody::captured($body, contentType: 'application/json', sha256: $sha));

        expect($result->bytes)->toBe($body)
            ->and($result->sha256)->toBe($sha);
    });

    it('store a form body byte for byte and keep its digest', function (): void {
        $body = 'a.b=1&tag=x&tag=y&q=a+b';
        $sha = hash('sha256', $body);

        $result = pathRedactor()->redactBody(CapturedBody::captured($body, contentType: 'application/x-www-form-urlencoded', sha256: $sha));

        expect($result->bytes)->toBe($body)
            ->and($result->sha256)->toBe($sha);
    });
});

describe('body path rules that match', function (): void {
    it('keep the JSON types of everything they did not touch', function (): void {
        $body = '{"id":12345678901234567890,"meta":{},"list":[],"amount":10.0,"user":{"pin":"4821","tags":{}},"password":"hunter2"}';

        $result = pathRedactor()->redactBody(CapturedBody::captured($body, contentType: 'application/json', sha256: hash('sha256', $body)));
        $bytes = (string) $result->bytes;

        expect($bytes)->toContain('"id":12345678901234567890')
            ->and($bytes)->toContain('"meta":{}')
            ->and($bytes)->toContain('"list":[]')
            ->and($bytes)->toContain('"amount":10.0')
            ->and($bytes)->toContain('"tags":{}')
            ->and($bytes)->toContain('"pin":"[REDACTED]"')
            ->and($bytes)->toContain('"password":"[REDACTED]"')
            ->and($bytes)->not->toContain('hunter2')
            ->and($bytes)->not->toContain('4821')
            // The digest describes bytes no longer stored.
            ->and($result->sha256)->toBeNull();
    });

    it('redact form pairs in place, leaving every other pair as it was sent', function (): void {
        $body = 'a.b=1&tag=x&tag=y&q=a+b&password=secret1&bad=%zz';

        $result = pathRedactor()->redactBody(CapturedBody::captured($body, contentType: 'application/x-www-form-urlencoded'));

        expect($result->bytes)->toBe('a.b=1&tag=x&tag=y&q=a+b&password=%5BREDACTED%5D&bad=%zz');
    });

    it('redact every occurrence of a repeated form field', function (): void {
        $body = 'password=first-secret&x=1&password=second-secret';

        $result = pathRedactor()->redactBody(CapturedBody::captured($body, contentType: 'application/x-www-form-urlencoded'));

        expect($result->bytes)->toBe('password=%5BREDACTED%5D&x=1&password=%5BREDACTED%5D');
    });

    it('learn every occurrence of a repeated form field', function (): void {
        $result = pathRedactor()->redact(exchange(
            requestBody: CapturedBody::captured('password=first-secret-value&password=second-secret-value', contentType: 'application/x-www-form-urlencoded'),
            responseBody: CapturedBody::captured('{"echo":"first-secret-value"}', contentType: 'application/json'),
        ));

        expect((string) $result->responseBody->bytes)->not->toContain('first-secret-value');
    });

    it('splice a hash-hinted placeholder in place too', function (): void {
        $redactor = new Redactor(new RedactionConfig(bodyPaths: ['password'], hashHint: true, hashSalt: 'salt'));

        $bytes = (string) $redactor->redactBody(CapturedBody::captured('q=a+b&password=hunter2', contentType: 'application/x-www-form-urlencoded'))->bytes;

        expect($bytes)->toStartWith('q=a+b&password=%5BREDACTED%3A')
            ->and($bytes)->not->toContain('hunter2');
    });

    it('redact nested form fields by their bracketed names', function (): void {
        $body = 'user%5Bname%5D=bob&user[pin]=4821&keep=1';

        $result = pathRedactor()->redactBody(CapturedBody::captured($body, contentType: 'application/x-www-form-urlencoded'));

        expect($result->bytes)->toBe('user%5Bname%5D=bob&user[pin]=%5BREDACTED%5D&keep=1');
    });

    it('redact every field beneath a named parent', function (): void {
        $redactor = new Redactor(new RedactionConfig(bodyPaths: ['card']));
        $body = 'card[number]=4111&card[cvc]=123&amount=5';

        $result = $redactor->redactBody(CapturedBody::captured($body, contentType: 'application/x-www-form-urlencoded'));

        expect($result->bytes)->toBe('card[number]=%5BREDACTED%5D&card[cvc]=%5BREDACTED%5D&amount=5');
    });

    it('match a field PHP would rename, as the rules always have', function (): void {
        // parse_str reads `pass word` and `pass.word` as `pass_word`; a rule
        // written against that name kept working.
        $redactor = new Redactor(new RedactionConfig(bodyPaths: ['pass_word']));

        $result = $redactor->redactBody(CapturedBody::captured('pass.word=s3cret&x=1', contentType: 'application/x-www-form-urlencoded'));

        expect($result->bytes)->toBe('pass.word=%5BREDACTED%5D&x=1');
    });

    it('fall back to rebuilding a form body rather than leave a targeted field behind', function (): void {
        // `items[]` is numbered by position, which a name read on its own
        // cannot know. The rule names the second item; the splice cannot
        // find it, so the body is rebuilt from what parse_str read.
        $redactor = new Redactor(new RedactionConfig(bodyPaths: ['items.1.card']));
        $body = 'items[][card]=4000001&items[][card]=4000002';

        $bytes = (string) $redactor->redactBody(CapturedBody::captured($body, contentType: 'application/x-www-form-urlencoded'))->bytes;

        expect($bytes)->not->toContain('4000002')
            ->and($bytes)->toContain('4000001');
    });

    it('rewrite only the pair a detector changed in a form body', function (): void {
        $body = 'q=a+b&card=4111+1111+1111+1111&bad=%zz';

        $result = (new Redactor())->redactBody(CapturedBody::captured($body, contentType: 'application/x-www-form-urlencoded'));

        expect($result->bytes)->toBe('q=a+b&card=%5BREDACTED%5D&bad=%zz');
    });
});

describe('URLs with nothing to redact', function (): void {
    it('are stored byte for byte', function (string $uri): void {
        expect((new Redactor())->redactUrl($uri))->toBe($uri);
    })->with([
        'plus and comma' => ['https://api.example.com/search?q=a+b&sort=name,asc&filter[x]=1&t=2026-09-23T10:00:00Z&bad=%zz'],
        'signed url' => ['https://s3.example.com/obj?X-Amz-Date=20260923T000000Z&X-Amz-SignedHeaders=host;range&name=a~b*c'],
        'scheme-relative' => ['//cdn.example.com/x?y=1'],
    ]);

    it('are stored byte for byte as the exchange URI', function (): void {
        $uri = 'https://api.example.com/search?q=a+b&sort=name,asc&bad=%zz#frag';

        expect((new Redactor())->redact(exchange(uri: $uri))->uri)->toBe($uri);
    });
});

describe('URLs with something to redact', function (): void {
    it('splice only the redacted pair', function (): void {
        $uri = 'https://api.example.com/search?q=a+b&token=abc123&sort=name,asc&bad=%zz#frag';

        expect((new Redactor())->redactUrl($uri))
            ->toBe('https://api.example.com/search?q=a+b&token=%5BREDACTED%5D&sort=name,asc&bad=%zz#frag');
    });

    it('keep a scheme-relative URL scheme-relative', function (): void {
        expect((new Redactor())->redactUrl('//cdn.example.com/x?token=abc123&y=1'))
            ->toBe('//cdn.example.com/x?token=%5BREDACTED%5D&y=1');
    });

    it('replace userinfo in place', function (): void {
        expect((new Redactor())->redactUrl('https://bob:hunter2@api.example.com/x?q=a+b'))
            ->toBe('https://[REDACTED]:[REDACTED]@api.example.com/x?q=a+b');
    });

    it('still learn what they removed', function (): void {
        $result = (new Redactor())->redact(exchange(
            uri: 'https://api.example.com/x?token=ordinary-secret-value&q=a+b',
            responseBody: CapturedBody::captured('{"echo":"ordinary-secret-value"}', contentType: 'application/json'),
        ));

        expect($result->uri)->toBe('https://api.example.com/x?token=%5BREDACTED%5D&q=a+b')
            ->and((string) $result->responseBody->bytes)->not->toContain('ordinary-secret-value');
    });
});

describe('show pretty-printing', function (): void {
    it('does not rewrite the JSON it displays', function (): void {
        $dir = sys_get_temp_dir() . '/wiretap-pretty-' . bin2hex(random_bytes(6));
        $body = '{"id":12345678901234567890,"meta":{},"amount":10.0}';

        (new NdjsonFileSink($dir))->write(exchange(
            responseHeaders: Headers::empty(),
            responseBody: CapturedBody::captured($body, contentType: 'application/json'),
        ));

        $stream = fopen('php://memory', 'w+b');
        assert(is_resource($stream));
        (new ShowCommand(new NdjsonReader($dir), new Output($stream, decorated: false), $dir))->handle(Input::fromArgv(['1']));
        rewind($stream);
        $shown = (string) stream_get_contents($stream);

        foreach (glob($dir . '/*') ?: [] as $file) {
            @unlink($file);
        }

        @rmdir($dir);

        expect($shown)->toContain('"id": 12345678901234567890')
            ->and($shown)->toContain('"meta": {}')
            ->and($shown)->toContain('"amount": 10.0');
    });
});
