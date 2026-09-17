<?php

declare(strict_types=1);

namespace Ssx\Wiretap\Cli;

/**
 * Minimal argv parsing.
 *
 * Hand-rolled on purpose. The core package's one selling point as a dependency
 * is that it requires nothing but PHP, and pulling in a console component so
 * that six commands can parse `--host=` would spend that for very little.
 *
 * Supports `--flag`, `--key=value`, `--key value`, `-abc` short clusters, and
 * positional arguments.
 */
final readonly class Input
{
    /**
     * @param list<string>          $arguments
     * @param array<string, string|bool> $options
     */
    private function __construct(
        public array $arguments,
        public array $options,
    ) {
    }

    /**
     * @param list<string> $argv
     */
    public static function fromArgv(array $argv): self
    {
        $arguments = [];
        $options = [];
        $count = count($argv);

        for ($i = 0; $i < $count; ++$i) {
            $token = $argv[$i];

            if (str_starts_with($token, '--')) {
                $name = substr($token, 2);

                if (str_contains($name, '=')) {
                    [$name, $value] = explode('=', $name, 2);
                    $options[$name] = $value;

                    continue;
                }

                // `--key value`, but only when the next token is not itself an
                // option — otherwise `--follow --host x` would swallow --host.
                $next = $argv[$i + 1] ?? null;

                if ($next !== null && !str_starts_with($next, '-')) {
                    $options[$name] = $next;
                    ++$i;

                    continue;
                }

                $options[$name] = true;

                continue;
            }

            if (str_starts_with($token, '-') && strlen($token) > 1) {
                foreach (str_split(substr($token, 1)) as $letter) {
                    $options[$letter] = true;
                }

                continue;
            }

            $arguments[] = $token;
        }

        return new self($arguments, $options);
    }

    public function argument(int $position, ?string $default = null): ?string
    {
        return $this->arguments[$position] ?? $default;
    }

    public function option(string $name, ?string $default = null): ?string
    {
        $value = $this->options[$name] ?? null;

        return is_string($value) ? $value : $default;
    }

    public function flag(string ...$names): bool
    {
        foreach ($names as $name) {
            if (($this->options[$name] ?? false) !== false) {
                return true;
            }
        }

        return false;
    }

    public function integer(string $name, int $default): int
    {
        $value = $this->option($name);

        return $value !== null && is_numeric($value) ? (int) $value : $default;
    }
}
