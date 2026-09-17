<?php

declare(strict_types=1);

use Ssx\Wiretap\Blocklist\Blocklist;
use Ssx\Wiretap\Blocklist\EnvBlocklistProvider;
use Ssx\Wiretap\Cli\Command\DoctorCommand;
use Ssx\Wiretap\Cli\Input;
use Ssx\Wiretap\Cli\Output;
use Ssx\Wiretap\Contract\BlocklistProvider;
use Ssx\Wiretap\Reader\NdjsonReader;
use Ssx\Wiretap\Recorder;
use Ssx\Wiretap\Redaction\RedactionConfig;
use Ssx\Wiretap\Redaction\Redactor;
use Ssx\Wiretap\Wiretap;

function runDoctor(): string
{
    $stream = fopen('php://memory', 'r+b');
    $dir = sys_get_temp_dir() . '/wiretap-doctor-' . bin2hex(random_bytes(6));

    $command = new DoctorCommand(new NdjsonReader($dir), new Output($stream, decorated: false), $dir);
    $command->handle(Input::fromArgv([]));

    rewind($stream);
    $out = (string) stream_get_contents($stream);
    fclose($stream);

    return $out;
}

afterEach(function (): void {
    Wiretap::reset();
    putenv('WIRETAP_BLOCK');
});

describe('doctor reports the safety controls', function (): void {
    it('shows how many blocklist rules are loaded and where they came from', function (): void {
        putenv('WIRETAP_BLOCK=*.gateway.example.com');

        Wiretap::setRecorder(new Recorder(
            blocklist: new Blocklist([new EnvBlocklistProvider()]),
        ));

        expect(runDoctor())
            ->toContain('Safety controls')
            ->toContain('blocklist rules')
            ->toContain('env:WIRETAP_BLOCK');
    });

    it('surfaces a rule that failed to compile', function (): void {
        // Previously invisible: the rule silently did not exist, and the only
        // evidence was traffic appearing that the operator believed was
        // blocked — which is the same signal a working blocklist produces.
        putenv('WIRETAP_BLOCK=~^https://unterminated');

        Wiretap::setRecorder(new Recorder(
            blocklist: new Blocklist([new EnvBlocklistProvider()]),
        ));

        expect(runDoctor())->toContain('closing delimiter');
    });

    it('says so when a provider failed and everything is being blocked', function (): void {
        $broken = new class implements BlocklistProvider {
            public function name(): string
            {
                return 'broken-provider';
            }

            public function patterns(): iterable
            {
                throw new RuntimeException('database unreachable');
            }
        };

        Wiretap::setRecorder(new Recorder(blocklist: new Blocklist([$broken])));

        expect(runDoctor())
            ->toContain('failed closed')
            ->toContain('database unreachable');
    });

    it('names a custom redaction pattern that can never run', function (): void {
        Wiretap::setRecorder(new Recorder(
            redactor: new Redactor(new RedactionConfig(custom: ['/unterminated'])),
        ));

        expect(runDoctor())->toContain('custom pattern never runs');
    });

    it('warns when no blocklist rules are configured at all', function (): void {
        Wiretap::setRecorder(new Recorder(blocklist: new Blocklist()));

        expect(runDoctor())->toContain('No blocklist rules are configured');
    });
});

describe('option parsing', function (): void {
    it('does not let a flag swallow a following positional argument', function (): void {
        // `wiretap show --json 1` parsed `json` as "1" and left no positional
        // behind, so the command answered "Which one?" for a request that
        // named the record perfectly clearly.
        $input = Input::fromArgv(['show', '--json', '1']);

        expect($input->flag('json'))->toBeTrue()
            ->and($input->argument(1))->toBe('1');
    });

    it('still binds a value to an option that takes one', function (): void {
        $input = Input::fromArgv(['list', '--host', 'api.example.com', '--limit', '50', '--failed']);

        expect($input->option('host'))->toBe('api.example.com')
            ->and($input->integer('limit', 20))->toBe(50)
            ->and($input->flag('failed'))->toBeTrue()
            ->and($input->arguments)->toBe(['list']);
    });

    it('treats a value option with no value as a flag rather than eating the next switch', function (): void {
        $input = Input::fromArgv(['--host', '--failed']);

        expect($input->option('host'))->toBeNull()
            ->and($input->flag('failed'))->toBeTrue();
    });
});
