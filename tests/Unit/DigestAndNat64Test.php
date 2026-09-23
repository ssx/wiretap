<?php

declare(strict_types=1);

use Ssx\Wiretap\Blocklist\Blocklist;
use Ssx\Wiretap\Blocklist\Pattern;
use Ssx\Wiretap\Blocklist\PresetBlocklistProvider;
use Ssx\Wiretap\CapturedBody;
use Ssx\Wiretap\Redaction\RedactionConfig;
use Ssx\Wiretap\Redaction\Redactor;

describe('the digest of a body that was not stored', function (): void {
    it('is dropped for an omitted binary body when there is no salt', function (): void {
        // sha256('4821') is found by trying ten thousand PINs.
        $body = CapturedBody::captured('4821', contentType: 'application/octet-stream', sha256: hash('sha256', '4821'));

        $result = (new Redactor())->redactBody($body);

        expect($result->omittedReason)->toBe(CapturedBody::OMITTED_BINARY)
            ->and($result->sha256)->toBeNull();
    });

    it('is keyed with the salt for an omitted binary body when there is one', function (): void {
        $sha = hash('sha256', '4821');
        $body = CapturedBody::captured('4821', contentType: 'application/octet-stream', sha256: $sha);

        $result = (new Redactor(new RedactionConfig(hashSalt: 'per-install')))->redactBody($body);

        expect($result->sha256)->toBe(hash_hmac('sha256', $sha, 'per-install'))
            ->and($result->sha256)->not->toBe($sha);
    });

    it('is dropped for a body a capture layer omitted with a raw digest', function (string $reason): void {
        $body = CapturedBody::omitted($reason, 4, 'application/json', hash('sha256', '4821'));

        $result = (new Redactor())->redactBody($body);

        expect($result->omittedReason)->toBe($reason)
            ->and($result->size)->toBe(4)
            ->and($result->sha256)->toBeNull();
    })->with([
        CapturedBody::OMITTED_BINARY,
        CapturedBody::OMITTED_STREAMING,
        CapturedBody::OMITTED_NOT_READABLE,
        CapturedBody::OMITTED_DISABLED,
    ]);

    it('is dropped from an omitted body passing through the whole exchange', function (): void {
        $result = (new Redactor())->redact(exchange(
            requestBody: CapturedBody::omitted(CapturedBody::OMITTED_STREAMING, 6, 'text/plain', hash('sha256', '482193')),
        ));

        expect($result->requestBody->sha256)->toBeNull();
    });
});

describe('NAT64 addresses', function (): void {
    it('are blocked by the cloud-metadata preset', function (string $url): void {
        expect((new Blocklist([PresetBlocklistProvider::all()]))->blocks($url))->toBeTrue();
    })->with([
        'well-known prefix' => 'http://[64:ff9b::a9fe:a9fe]/latest/meta-data/',
        'well-known prefix, dotted' => 'http://[64:ff9b::169.254.169.254]/latest/meta-data/',
        'well-known prefix, expanded' => 'http://[0064:ff9b:0000:0000:0000:0000:a9fe:a9fe]/latest/meta-data/',
        // RFC 6052's /48 layout: v4 bits 0-15 at 48-63, the u octet at
        // 64-71, v4 bits 16-31 at 72-87.
        'local-use prefix' => 'http://[64:ff9b:1:a9fe:a9:fe00::]/latest/meta-data/',
    ]);

    it('place each octet of the /48 embedding where RFC 6052 puts it', function (): void {
        // 10.20.30.40 = 0a 14 1e 28: bytes 6-7 are 0a14, byte 8 is u, bytes
        // 9-10 are 1e28.
        $pattern = Pattern::compile('10.20.30.40');

        expect($pattern->matches('http://[64:ff9b:1:0a14:001e:2800::]/'))->toBeTrue()
            // The same bytes read as if the u octet were not there.
            ->and($pattern->matches('http://[64:ff9b:1:0a14:1e28::]/'))->toBeFalse()
            // The /96 layout inside the /48 prefix is a different address.
            ->and($pattern->matches('http://[64:ff9b:1::0a14:1e28]/'))->toBeFalse();
    });

    it('match a rule written as NAT64 against the plain IPv4 address, and back', function (): void {
        $rule = Pattern::compile('64:ff9b::7f00:1');

        expect($rule->matches('http://127.0.0.1/'))->toBeTrue()
            ->and(Pattern::compile('127.0.0.1')->matches('http://[64:ff9b::127.0.0.1]/'))->toBeTrue();
    });

    it('leave other addresses in and near the prefixes alone', function (string $url): void {
        expect((new Blocklist([PresetBlocklistProvider::all()]))->blocks($url))->toBeFalse();
    })->with([
        'other v4 via NAT64' => 'http://[64:ff9b::a9fe:a9fd]/',
        'outside the /96' => 'http://[64:ff9b:0:0:1::a9fe:a9fe]/',
        'outside the /48' => 'http://[64:ff9b:2:a9fe:a9:fe00::]/',
    ]);
});
