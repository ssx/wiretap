<?php

declare(strict_types=1);

use Ssx\Wiretap\CapturedBody;
use Ssx\Wiretap\Cli\Command\ShowCommand;
use Ssx\Wiretap\Cli\Input;
use Ssx\Wiretap\Cli\Output;
use Ssx\Wiretap\Headers;
use Ssx\Wiretap\Reader\NdjsonReader;
use Ssx\Wiretap\Sink\NdjsonFileSink;

/**
 * `wiretap show --curl` run against a real server: a record whose request
 * headers are the complete set must replay as that set, without the curl
 * CLI's own Accept and User-Agent added on top.
 */
const CURL_EXPORT_PORT = 18796;

beforeAll(function (): void {
    if (trim((string) shell_exec('command -v curl')) === '') {
        return;
    }

    $docroot = sys_get_temp_dir() . '/wiretap-curl-export';
    @mkdir($docroot, 0o755, true);
    file_put_contents($docroot . '/index.php', '<?php header("Content-Type: application/json"); echo json_encode(getallheaders());');

    $server = proc_open(
        sprintf('exec %s -S 127.0.0.1:%d -t %s', PHP_BINARY, CURL_EXPORT_PORT, escapeshellarg($docroot)),
        [1 => ['file', '/dev/null', 'w'], 2 => ['file', '/dev/null', 'w']],
        $pipes,
    );

    for ($i = 0; $i < 50; ++$i) {
        $socket = @fsockopen('127.0.0.1', CURL_EXPORT_PORT, $errno, $errstr, 0.1);

        if ($socket !== false) {
            fclose($socket);

            break;
        }

        usleep(100_000);
    }

    $owner = getmypid();
    register_shutdown_function(static function () use ($server, $owner): void {
        if (getmypid() === $owner) {
            proc_terminate($server);
            proc_close($server);
        }
    });
});

beforeEach(function (): void {
    if (trim((string) shell_exec('command -v curl')) === '') {
        $this->markTestSkipped('needs the curl CLI');
    }

    $this->dir = sys_get_temp_dir() . '/wiretap-curl-export-log-' . bin2hex(random_bytes(4));
});

afterEach(function (): void {
    foreach (glob($this->dir . '/*') ?: [] as $file) {
        @unlink($file);
    }

    @rmdir($this->dir);
});

/**
 * Store one record, export it with `show --curl`, run the command, and return
 * the request headers the server received, keyed by lower-cased name.
 *
 * @param array<string, mixed> $context
 * @param list<array{string, string}> $headers
 *
 * @return array<string, string>
 */
function replayed(string $dir, array $headers, array $context, ?CapturedBody $body = null): array
{
    (new NdjsonFileSink($dir))->write(exchange(
        uri: 'http://127.0.0.1:' . CURL_EXPORT_PORT . '/',
        method: $body === null ? 'GET' : 'POST',
        requestHeaders: Headers::fromPairs($headers),
        requestBody: $body,
    )->withContext($context));

    $stream = fopen('php://memory', 'w+b');
    (new ShowCommand(new NdjsonReader($dir), new Output($stream, decorated: false), $dir))
        ->handle(Input::fromArgv(['1', '--curl']));
    rewind($stream);

    $received = json_decode((string) shell_exec(stream_get_contents($stream) . ' -s'), true);
    expect($received)->toBeArray();

    return array_change_key_case($received, CASE_LOWER);
}

it('does not let the curl CLI add Accept or User-Agent to a complete header set', function (string $marker): void {
    $received = replayed($this->dir, [['Host', '127.0.0.1:' . CURL_EXPORT_PORT], ['X-Trace', 't1']], ['request_headers' => $marker]);

    // Guzzle removes curl's Accept, and libcurl sends no User-Agent of its
    // own, so neither was on the wire.
    expect($received)->not->toHaveKey('accept')
        ->and($received)->not->toHaveKey('user-agent')
        ->and($received['x-trace'])->toBe('t1');
})->with(['reconstructed', 'sent']);

it('still sends the Accept and User-Agent a record does carry', function (): void {
    $received = replayed($this->dir, [['Accept', 'application/json'], ['User-Agent', 'app/2']], ['request_headers' => 'reconstructed']);

    expect($received['accept'])->toBe('application/json')
        ->and($received['user-agent'])->toBe('app/2');
});

it('leaves a partial header set to the curl CLI, since it may be missing them', function (): void {
    // Older records carry only the headers the application configured, so
    // their absence says nothing about what was sent.
    $received = replayed($this->dir, [['X-Trace', 't1']], ['request_headers' => 'configured']);

    expect($received)->toHaveKey('accept')
        ->and($received)->toHaveKey('user-agent');
});

it('replays a form body with the headers on record', function (): void {
    $received = replayed(
        $this->dir,
        [['Host', '127.0.0.1:' . CURL_EXPORT_PORT], ['Content-Type', 'application/x-www-form-urlencoded']],
        ['request_headers' => 'reconstructed'],
        CapturedBody::captured('a=1', contentType: 'application/x-www-form-urlencoded'),
    );

    expect($received)->not->toHaveKey('accept')
        ->and($received)->not->toHaveKey('user-agent')
        ->and($received['content-type'])->toBe('application/x-www-form-urlencoded')
        ->and($received['content-length'])->toBe('3');
});
