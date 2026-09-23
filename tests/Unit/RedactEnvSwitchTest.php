<?php

declare(strict_types=1);

use Ssx\Wiretap\Headers;
use Ssx\Wiretap\Wiretap;

/**
 * WIRETAP_REDACT on the env-built default recorder: only an unmistakable
 * false turns redaction off.
 */
beforeEach(function (): void {
    $this->dir = sys_get_temp_dir() . '/wiretap-redact-env-' . bin2hex(random_bytes(4));
    putenv('WIRETAP_ENABLED=true');
    putenv('WIRETAP_PATH=' . $this->dir);
});

afterEach(function (): void {
    putenv('WIRETAP_ENABLED');
    putenv('WIRETAP_PATH');
    putenv('WIRETAP_REDACT');
    Wiretap::reset();

    foreach (glob($this->dir . '/*') ?: [] as $file) {
        @unlink($file);
    }

    @rmdir($this->dir);
});

/**
 * Record one exchange through the default recorder and return what was stored.
 */
function storedWith(?string $redact): string
{
    $redact === null ? putenv('WIRETAP_REDACT') : putenv('WIRETAP_REDACT=' . $redact);
    Wiretap::reset();

    $recorder = Wiretap::recorder();
    $recorder->record(exchange(
        requestHeaders: Headers::fromMap(['Authorization' => ['Bearer sk_live_plaintexttoken123']]),
    ));
    $recorder->flush();

    $stored = '';

    foreach (glob(Wiretap::defaultLogPath() . '/*') ?: [] as $file) {
        $stored .= (string) file_get_contents($file);
    }

    expect($stored)->not->toBe('');

    return $stored;
}

it('stores plaintext when WIRETAP_REDACT is explicitly false', function (string $off): void {
    expect(storedWith($off))->toContain('sk_live_plaintexttoken123');
})->with(['false', '0', 'off', 'no', ' FALSE ', 'Off']);

it('keeps redacting when WIRETAP_REDACT is unset, empty, true or a typo', function (?string $value): void {
    expect(storedWith($value))->not->toContain('sk_live_plaintexttoken123')
        ->and(storedWith($value))->toContain('[REDACTED]');
})->with([null, '', 'true', '1', 'flase', 'disabled', 'nope']);
