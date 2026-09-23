<?php

declare(strict_types=1);

namespace Ssx\Wiretap\Cli;

use Ssx\Wiretap\Wiretap;

use Ssx\Wiretap\Cli\Command\DoctorCommand;
use Ssx\Wiretap\Cli\Command\ExportCommand;
use Ssx\Wiretap\Cli\Command\ListCommand;
use Ssx\Wiretap\Cli\Command\PruneCommand;
use Ssx\Wiretap\Cli\Command\ShowCommand;
use Ssx\Wiretap\Cli\Command\TraceCommand;
use Ssx\Wiretap\Reader\NdjsonReader;

final class Application
{
    public const VERSION = '0.1.0';

    /** @var array<string, class-string> */
    private const COMMANDS = [
        'list' => ListCommand::class,
        'show' => ShowCommand::class,
        'trace' => TraceCommand::class,
        'export' => ExportCommand::class,
        'prune' => PruneCommand::class,
        'doctor' => DoctorCommand::class,
    ];

    public function __construct(private readonly Output $output = new Output())
    {
    }

    /**
     * @param list<string> $argv
     */
    public function run(array $argv): int
    {
        $command = $argv[1] ?? null;
        $input = Input::fromArgv(array_slice($argv, 2));

        if ($command === null || $command === 'help' || $input->flag('h', 'help')) {
            $this->usage();

            return 0;
        }

        if ($command === '--version' || $command === 'version') {
            $this->output->line('wiretap ' . self::VERSION);

            return 0;
        }

        if (!isset(self::COMMANDS[$command])) {
            $this->output->line($this->output->red("Unknown command: {$command}"));
            $this->output->line();
            $this->usage();

            return 1;
        }

        $path = $input->option('path') ?? Wiretap::defaultLogPath();
        $reader = new NdjsonReader($path);

        $class = self::COMMANDS[$command];
        /** @var object{handle: callable} $instance */
        $instance = new $class($reader, $this->output, $path);

        try {
            /** @phpstan-ignore-next-line dynamic dispatch over a closed command set */
            return (int) $instance->handle($input);
        } catch (\Throwable $e) {
            $this->output->line($this->output->red('Error: ' . $e->getMessage()));

            return 1;
        }
    }

    private function usage(): void
    {
        $o = $this->output;

        $o->line($o->bold('wiretap ') . $o->dim(self::VERSION));
        $o->line();
        $o->line($o->dim('  Outbound HTTP calls, as they actually happened.'));
        $o->line();
        $o->line($o->bold('USAGE'));
        $o->line('  wiretap <command> [options]');
        $o->line();
        $o->line($o->bold('COMMANDS'));
        $o->line('  ' . $o->cyan('list') . '     List recorded exchanges, newest first');
        $o->line('  ' . $o->cyan('show') . '     Show one exchange in full');
        $o->line('  ' . $o->cyan('trace') . '    Every call made during one inbound request');
        $o->line('  ' . $o->cyan('export') . '   Write HAR 1.2 for DevTools, Proxyman, Insomnia, Postman');
        $o->line('  ' . $o->cyan('prune') . '    Delete logs older than a retention window');
        $o->line('  ' . $o->cyan('doctor') . '   Report what is and is not being captured');
        $o->line();
        $o->line($o->bold('COMMON OPTIONS'));
        $o->line('  --path=DIR         Log directory (default: $WIRETAP_PATH or the system temp dir)');
        $o->line('  --host=HOST        Only this host');
        $o->line('  --method=METHOD    Only this HTTP method');
        $o->line('  --status=CODE      Exact status, or a class such as 5xx');
        $o->line('  --failed           Transport errors and 4xx/5xx only');
        $o->line('  --since=30m        Only records newer than this (or a Unix timestamp)');
        $o->line('  --until=2h         Only records older than this (or a Unix timestamp)');
        $o->line('  --limit=N          Maximum results (default 20)');
        $o->line();
        $o->line($o->bold('EXAMPLES'));
        $o->line($o->dim('  wiretap list --host=api.example.com --limit=20'));
        $o->line($o->dim('  wiretap list --failed'));
        $o->line($o->dim('  wiretap show 1'));
        $o->line($o->dim('  wiretap show 1 --curl'));
        $o->line($o->dim('  wiretap trace 01J2Q6...'));
        $o->line($o->dim('  wiretap export --failed > failures.har'));
        $o->line($o->dim('  wiretap prune --older-than=7d'));
    }
}
