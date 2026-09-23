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

    /**
     * Make recorded text safe to print to a terminal.
     *
     * Everything shown by list, show and trace came from a server or an
     * application, and a terminal acts on control sequences wherever they
     * appear: an OSC 52 sequence in a response header wrote to the operator's
     * clipboard, and CSI 2J cleared the screen to draw a fake one. C0 controls
     * (other than newline and tab), DEL and C1 controls are written as
     * visible escapes instead. Text that is not valid UTF-8 has every byte
     * above 0x7f escaped, since a terminal not in UTF-8 mode reads 0x9b alone
     * as CSI.
     */
    public static function clean(string $text): string
    {
        $pattern = preg_match('//u', $text) === 1
            ? '/[\x00-\x08\x0b-\x1f\x7f]|\xc2[\x80-\x9f]/'
            : '/[\x00-\x08\x0b-\x1f\x7f-\xff]/';

        return preg_replace_callback(
            $pattern,
            static fn (array $m): string => strlen($m[0]) === 2
                ? sprintf('\\u%04x', ord($m[0][1]))
                : sprintf('\\x%02x', ord($m[0])),
            $text,
        ) ?? (preg_replace('/[^\x20-\x7e\n\t]/', '?', $text) ?? '');
    }

    /**
     * Escape C1 controls in JSON output as \u0080-\u009f.
     *
     * JSON_UNESCAPED_UNICODE writes them as raw UTF-8, which some terminals
     * act on. The escaped form decodes to the same string, so the document
     * is unchanged; C0 controls are already escaped by json_encode.
     */
    public static function cleanJson(string $json): string
    {
        return preg_replace_callback(
            '/\xc2([\x80-\x9f])/',
            static fn (array $m): string => sprintf('\\u%04x', ord($m[1])),
            $json,
        ) ?? $json;
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
