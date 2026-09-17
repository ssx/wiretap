<?php

declare(strict_types=1);

namespace Ssx\Wiretap\Cli;

/**
 * Terminal output with colour, where the terminal will take it.
 */
final class Output
{
    private readonly bool $decorated;

    /** @param resource $stream */
    public function __construct(private $stream = STDOUT, ?bool $decorated = null)
    {
        $this->decorated = $decorated ?? $this->detectColourSupport();
    }

    public function write(string $text): void
    {
        fwrite($this->stream, $text);
    }

    public function line(string $text = ''): void
    {
        $this->write($text . PHP_EOL);
    }

    public function dim(string $text): string
    {
        return $this->decorate($text, '2');
    }

    public function bold(string $text): string
    {
        return $this->decorate($text, '1');
    }

    public function green(string $text): string
    {
        return $this->decorate($text, '32');
    }

    public function yellow(string $text): string
    {
        return $this->decorate($text, '33');
    }

    public function red(string $text): string
    {
        return $this->decorate($text, '31');
    }

    public function cyan(string $text): string
    {
        return $this->decorate($text, '36');
    }

    public function statusColour(?int $status): string
    {
        $text = $status === null ? 'ERR' : (string) $status;

        return match (true) {
            $status === null => $this->red($text),
            $status >= 500 => $this->red($text),
            $status >= 400 => $this->yellow($text),
            $status >= 200 && $status < 300 => $this->green($text),
            default => $text,
        };
    }

    private function decorate(string $text, string $code): string
    {
        return $this->decorated ? "\033[{$code}m{$text}\033[0m" : $text;
    }

    private function detectColourSupport(): bool
    {
        if (getenv('NO_COLOR') !== false) {
            return false;
        }

        if (!is_resource($this->stream)) {
            return false;
        }

        return function_exists('stream_isatty') && @stream_isatty($this->stream);
    }
}
