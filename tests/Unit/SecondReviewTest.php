<?php

declare(strict_types=1);

use Ssx\Wiretap\Blocklist\ArrayBlocklistProvider;
use Ssx\Wiretap\Blocklist\Blocklist;
use Ssx\Wiretap\Blocklist\EnvBlocklistProvider;
use Ssx\Wiretap\CapturedBody;
use Ssx\Wiretap\Headers;
use Ssx\Wiretap\Redaction\RedactionConfig;
use Ssx\Wiretap\Redaction\Redactor;

/**
 * Findings from the second review round. Several are regressions introduced by
 * the fixes for the first round, which is why each is written as the leak that
 * was possible rather than as the implementation.
 */

describe('secrets learned across the whole exchange', function (): void {
    it('sweeps a query secret out of an ordinary response header', function (): void {
        // Headers ran the detectors but never the known-secret sweep, so a
        // value stripped from the URI came back in X-Echo untouched.
        $exchange = exchange(
            uri: 'https://api.example.com/v1?token=ordinary-secret-value',
            responseHeaders: Headers::fromRaw('X-Echo: ordinary-secret-value'),
        );

        expect((new Redactor())->redact($exchange)->responseHeaders->first('X-Echo'))
            ->not->toContain('ordinary-secret-value');
    });

    it('registers a value removed by a body path as a known secret', function (): void {
        // The structural redactor removed it from the request and never told
        // KnownSecrets, so the same string in the response survived.
        $redactor = new Redactor(new RedactionConfig(bodyPaths: ['password']));

        $exchange = exchange(
            requestBody: CapturedBody::captured(
                json_encode(['password' => 'ordinary-secret-value']),
                contentType: 'application/json',
            ),
            responseBody: CapturedBody::captured(
                json_encode(['echo' => 'ordinary-secret-value']),
                contentType: 'application/json',
            ),
        );

        $result = $redactor->redact($exchange);

        expect($result->requestBody->bytes)->not->toContain('ordinary-secret-value')
            ->and($result->responseBody->bytes)->not->toContain('ordinary-secret-value');
    });

    it('protects a body echoing a secret from a header that appears after it', function (): void {
        // Sweeping as we went meant ordering decided whether a secret was
        // caught. Collecting first removes that dependence.
        $exchange = exchange(
            responseBody: CapturedBody::captured(
                json_encode(['echo' => 'Bearer tok_ordinarysecretvalue']),
                contentType: 'application/json',
            ),
            requestHeaders: Headers::fromRaw('Authorization: Bearer tok_ordinarysecretvalue'),
        );

        expect((new Redactor())->redact($exchange)->responseBody->bytes)
            ->not->toContain('tok_ordinarysecretvalue');
    });

    it('runs the detectors over the uri itself', function (): void {
        // redactUrl only removes *named* parameters, so a card number in an
        // unnamed one was stored in full with PAN detection enabled.
        $exchange = exchange(uri: 'https://api.example.com/pay?ref=4111111111111111');

        expect((new Redactor())->redact($exchange)->uri)->not->toContain('4111111111111111');
    });
});

describe('regex execution failure', function (): void {
    it('drops the body rather than restoring the secret it could not remove', function (): void {
        // preg_replace_callback returns null on invalid UTF-8 in the subject.
        // Falling back to the original subject restored the very value the
        // pattern existed to remove.
        $redactor = new Redactor(new RedactionConfig(
            patterns: [],
            custom: ['/ordinary-secret/u'],
        ));

        $result = $redactor->redactBody(CapturedBody::captured(
            "ordinary-secret\xff",
            contentType: 'text/plain',
        ));

        expect($result->isPresent() ? (string) $result->bytes : '')
            ->not->toContain('ordinary-secret');
    });
});

describe('the blocklist tokenizer', function (): void {
    it('keeps a regex containing an escaped tilde in one piece', function (): void {
        // The tilde handling added in the first round treated \~ as the
        // closing delimiter, split the rule at its quantifier comma, and
        // discarded it — so the traffic it existed to block was captured.
        $patterns = EnvBlocklistProvider::parse('~^https://example[.]com/\~user/[0-9]{1,3}$~');

        expect($patterns)->toHaveCount(1);

        $blocklist = new Blocklist([new ArrayBlocklistProvider($patterns)]);

        expect($blocklist->errors())->toBeEmpty()
            ->and($blocklist->blocks('https://example.com/~user/12'))->toBeTrue();
    });

    it('still treats a literal double backslash as not escaping', function (): void {
        expect(EnvBlocklistProvider::parse('~^a\\\\~,b.example.com'))->toHaveCount(2);
    });
});

describe('the file sink rollback', function (): void {
    it('never truncates away another writer\'s committed records', function (): void {
        // The rollback position came from ftell() on a handle opened before
        // the lock, so a concurrent append could leave it behind EOF — and a
        // failed write would then delete that other writer's data.
        $dir = sys_get_temp_dir() . '/wiretap-rollback-' . bin2hex(random_bytes(6));

        try {
            $sink = new \Ssx\Wiretap\Sink\NdjsonFileSink($dir);
            $sink->write(exchange(uri: 'https://api.example.com/first'));

            // Simulate another process appending directly.
            file_put_contents($sink->currentFile(), "{\"id\":\"other\"}\n", FILE_APPEND);

            $sink->write(exchange(uri: 'https://api.example.com/third'));

            $lines = array_values(array_filter(explode("\n", (string) file_get_contents($sink->currentFile()))));

            expect($lines)->toHaveCount(3)
                ->and(implode("\n", $lines))->toContain('other');
        } finally {
            foreach (glob($dir . '/*') ?: [] as $f) {
                unlink($f);
            }
            if (is_dir($dir)) {
                rmdir($dir);
            }
        }
    });
});

describe('alternate JSON escapes', function (): void {
    it('scrubs a secret written with a unicode escape', function (): void {
        // o is an ordinary way to write "o". Enumerating encodings could
        // never be complete, so the comparison is done on decoded values.
        $exchange = exchange(
            uri: 'https://api.example.com/v1?token=ordinary-secret-value',
            responseBody: CapturedBody::captured(
                '{"echo":"ordinary-secret-value"}',
                contentType: 'application/json',
            ),
        );

        $result = (new Redactor())->redact($exchange);
        $decoded = json_decode((string) $result->responseBody->bytes, true);

        expect(json_encode($decoded))->not->toContain('rdinary-secret-value');
    });
});

describe('blocked host counters', function (): void {
    it('does not grow one entry per host forever', function (): void {
        $blocklist = new Blocklist([new ArrayBlocklistProvider(['*.example.com'])]);

        for ($i = 0; $i < 1000; ++$i) {
            $blocklist->blocks("https://host{$i}.example.com/x");
        }

        expect(count($blocklist->blockCounts()))->toBeLessThanOrEqual(257);
    });
});
