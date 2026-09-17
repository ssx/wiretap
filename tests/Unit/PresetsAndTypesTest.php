<?php

declare(strict_types=1);

use Ssx\Wiretap\Blocklist\Blocklist;
use Ssx\Wiretap\Blocklist\PresetBlocklistProvider;
use Ssx\Wiretap\CapturedBody;
use Ssx\Wiretap\Contract\BlocklistProvider;
use Ssx\Wiretap\Redaction\Redactor;

describe('capturable content types', function (): void {
    it('captures a structured syntax suffix type', function (string $contentType): void {
        // Listing individual vendor types could never keep up: only two of the
        // dozens of +json types in use were in the list, so the rest were
        // recorded as binary and dropped.
        $result = (new Redactor())->redactBody(
            CapturedBody::captured('{"a":1}', contentType: $contentType),
        );

        expect($result->isPresent())->toBeTrue();
    })->with([
        'json api' => 'application/vnd.api+json',
        'hal' => 'application/hal+json',
        'github' => 'application/vnd.github+json',
        'problem' => 'application/problem+json',
        'linked data' => 'application/ld+json',
        'atom' => 'application/atom+xml',
        'ndjson' => 'application/x-ndjson',
        'with charset' => 'application/vnd.api+json; charset=utf-8',
    ]);

    it('still drops genuinely binary types', function (string $contentType): void {
        $result = (new Redactor())->redactBody(
            CapturedBody::captured('binary', contentType: $contentType),
        );

        expect($result->isPresent())->toBeFalse()
            ->and($result->omittedReason)->toBe(CapturedBody::OMITTED_BINARY);
    })->with([
        'png' => 'image/png',
        'octet stream' => 'application/octet-stream',
        'pdf' => 'application/pdf',
        'zip' => 'application/zip',
    ]);
});

describe('cloud metadata preset', function (): void {
    it('blocks every route to an instance metadata service', function (string $url): void {
        // A metadata response carries short-lived IAM credentials.
        $blocklist = new Blocklist([new PresetBlocklistProvider([PresetBlocklistProvider::CLOUD_METADATA])]);

        expect($blocklist->blocks($url))->toBeTrue();
    })->with([
        'aws ipv4' => 'http://169.254.169.254/latest/meta-data/iam/security-credentials/',
        'aws ipv6' => 'http://[fd00:ec2::254]/latest/meta-data/iam/security-credentials/',
        'gce fqdn' => 'http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/',
        'gce short name' => 'http://metadata/computeMetadata/v1/instance/service-accounts/',
        'alibaba' => 'http://100.100.100.200/latest/meta-data/',
    ]);

    it('does not block ordinary traffic', function (): void {
        $blocklist = new Blocklist([new PresetBlocklistProvider([PresetBlocklistProvider::CLOUD_METADATA])]);

        expect($blocklist->blocks('https://api.example.com/v1/orders'))->toBeFalse();
    });
});

describe('failed-closed recovery', function (): void {
    it('retries the providers once the window has passed', function (): void {
        // A database unreachable at the first blocks() call used to block all
        // capture for the life of the process — safe, but one transient blip
        // cost a worker its whole shift of debugging.
        $provider = new class implements BlocklistProvider {
            public bool $broken = true;

            public function name(): string
            {
                return 'flaky';
            }

            public function patterns(): iterable
            {
                if ($this->broken) {
                    throw new RuntimeException('database unreachable');
                }

                return ['*.gateway.example.com'];
            }
        };

        $blocklist = new Blocklist([$provider], retryFailedAfterSeconds: 1);

        expect($blocklist->blocks('https://api.example.com/'))->toBeTrue();

        $provider->broken = false;

        // Still held: the window has not passed, so this must not recompile.
        expect($blocklist->blocks('https://api.example.com/'))->toBeTrue();

        sleep(2);

        expect($blocklist->blocks('https://api.example.com/'))->toBeFalse()
            ->and($blocklist->blocks('https://x.gateway.example.com/'))->toBeTrue()
            ->and($blocklist->hasFailedClosed())->toBeFalse();
    });

    it('recovers immediately when invalidated explicitly', function (): void {
        $provider = new class implements BlocklistProvider {
            public bool $broken = true;

            public function name(): string
            {
                return 'flaky';
            }

            public function patterns(): iterable
            {
                if ($this->broken) {
                    throw new RuntimeException('database unreachable');
                }

                return [];
            }
        };

        $blocklist = new Blocklist([$provider]);

        expect($blocklist->blocks('https://api.example.com/'))->toBeTrue();

        $provider->broken = false;
        $blocklist->invalidate();

        expect($blocklist->blocks('https://api.example.com/'))->toBeFalse();
    });

    it('keeps blocking while the provider is still broken', function (): void {
        $provider = new class implements BlocklistProvider {
            public function name(): string
            {
                return 'always-broken';
            }

            public function patterns(): iterable
            {
                throw new RuntimeException('database unreachable');
            }
        };

        $blocklist = new Blocklist([$provider], retryFailedAfterSeconds: 1);

        expect($blocklist->blocks('https://api.example.com/'))->toBeTrue();

        sleep(2);

        expect($blocklist->blocks('https://api.example.com/'))->toBeTrue();
    });
});
