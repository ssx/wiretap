<?php

declare(strict_types=1);

use Ssx\Wiretap\CapturedBody;
use Ssx\Wiretap\Exchange;
use Ssx\Wiretap\Export\HarExporter;
use Ssx\Wiretap\Headers;
use Ssx\Wiretap\Redaction\RedactionConfig;
use Ssx\Wiretap\Redaction\Redactor;
use Ssx\Wiretap\Support\QueryString;
use Ssx\Wiretap\Timings;

/**
 * @param list<string> $context
 */
function queryExchange(string $uri, string $body = '{}', array $context = []): Exchange
{
    return new Exchange(
        id: 'x',
        correlationId: 'c',
        transport: 'curl',
        method: 'POST',
        uri: $uri,
        requestHeaders: Headers::empty(),
        requestBody: CapturedBody::none(),
        status: 200,
        reason: 'OK',
        responseHeaders: Headers::empty(),
        responseBody: CapturedBody::captured($body, contentType: 'application/json'),
        timings: new Timings(total: 1),
        error: null,
        startedAt: 1.0,
        context: $context,
    );
}

describe('QueryString', function (): void {
    it('round-trips pairs that parse_str would lose or rewrite', function (string $query): void {
        expect(QueryString::build(QueryString::parse($query)))->toBe($query);
    })->with([
        'repeated name' => 'token=A&token=B',
        'dot in name' => 'a.b=1&c=2',
        'empty value' => 'a=&b=1',
        'encoded space' => 'c%20d=2',
    ]);

    it('keeps a valueless pair distinct from an empty one', function (): void {
        expect(QueryString::parse('flag&a='))->toBe([['flag', null], ['a', '']])
            ->and(QueryString::build([['flag', null], ['a', '']]))->toBe('flag&a=');
    });

    it('reads a subscripted name as its base name', function (): void {
        expect(QueryString::baseName('token[]'))->toBe('token')
            ->and(QueryString::baseName('token[0]'))->toBe('token')
            ->and(QueryString::baseName('token'))->toBe('token');
    });

    it('parses past max_input_vars without truncating or warning', function (): void {
        $query = implode('&', array_map(static fn (int $i): string => "f{$i}=v{$i}", range(1, 1200)));

        $raised = null;
        set_error_handler(function (int $_, string $message) use (&$raised): bool {
            $raised = $message;

            return true;
        });

        try {
            $pairs = QueryString::parse($query);
        } finally {
            restore_error_handler();
        }

        expect($pairs)->toHaveCount(1200)->and($raised)->toBeNull();
    });
});

describe('query redaction', function (): void {
    it('learns every value of a repeated sensitive name', function (): void {
        // parse_str kept only the last value, so the first was never learned
        // as a secret and a response echoing it was stored in plaintext.
        $result = (new Redactor())->redact(queryExchange(
            'https://h/?token=AAAordinaryfirst&token=BBBordinarysecond',
            '{"echo":"AAAordinaryfirst"}',
        ));

        expect($result->responseBody->bytes)->not->toContain('AAAordinaryfirst')
            ->and($result->uri)->toBe('https://h/?token=%5BREDACTED%5D&token=%5BREDACTED%5D');
    });

    it('redacts a subscripted sensitive parameter', function (): void {
        $result = (new Redactor())->redact(queryExchange('https://h/?token[]=ordinarysecretvalue'));

        expect($result->uri)->not->toContain('ordinarysecretvalue');
    });

    it('replaces a context entry rather than appending the redacted copy', function (): void {
        // The spread renumbered integer keys, so the plaintext stayed in the
        // record beside its own redaction.
        $result = (new Redactor())->redact(queryExchange(
            'https://h/?token=ordinarysecretvalue',
            '{}',
            ['https://h/?token=ordinarysecretvalue'],
        ));

        expect($result->context)->toHaveCount(1)
            ->and(json_encode($result->context))->not->toContain('ordinarysecretvalue');
    });
});

describe('form bodies', function (): void {
    it('returns an unchanged form body byte for byte', function (): void {
        $body = 'a=1&a=2&b.c=3';

        $result = (new Redactor())->redactBody(
            CapturedBody::captured($body, contentType: 'application/x-www-form-urlencoded'),
        );

        expect($result->bytes)->toBe($body);
    });

    it('does not mark a form body inspected when parse_str truncated it', function (): void {
        // Over max_input_vars, parse_str drops the tail and warns. The named
        // field was never looked at, so the body must not be treated as
        // successfully inspected — and the warning must not escape into the
        // host's error handler, where a framework turns it into an exception
        // thrown from inside the instrumentation.
        $body = implode('&', array_map(static fn (int $i): string => "f{$i}=v{$i}", range(1, 1200)))
            . '&password=ordinarysecretvalue';

        $redactor = new Redactor(new RedactionConfig(bodyPaths: ['password']));

        $escaped = null;
        set_error_handler(function (int $_, string $message) use (&$escaped): bool {
            $escaped = $message;

            return true;
        });

        try {
            $result = $redactor->redactBody(
                CapturedBody::captured($body, contentType: 'application/x-www-form-urlencoded'),
            );
        } finally {
            restore_error_handler();
        }

        expect($escaped)->toBeNull()
            ->and($result->isPresent())->toBeFalse()
            ->and($result->omittedReason)->toBe(CapturedBody::OMITTED_REDACTED);
    });
});

describe('HAR export', function (): void {
    it('exports every value of a repeated query name', function (): void {
        $har = (new HarExporter())->export([queryExchange('https://h/?a=1&a=2&b.c=3')]);

        $params = $har['log']['entries'][0]['request']['queryString'];

        expect($params)->toBe([
            ['name' => 'a', 'value' => '1'],
            ['name' => 'a', 'value' => '2'],
            ['name' => 'b.c', 'value' => '3'],
        ]);
    });
});
