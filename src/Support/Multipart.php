<?php

declare(strict_types=1);

namespace Ssx\Wiretap\Support;

/**
 * A multipart/form-data body, split into parts it can be rebuilt from.
 *
 * Deliberately strict. This exists so the redactor can see each field, and a
 * body it cannot read exactly is one whose secrets it cannot find, so parse()
 * returns null for anything unusual rather than guessing: no boundary, a
 * preamble or epilogue, bare-LF line endings, folded headers, a part with no
 * form-data name, a Content-Transfer-Encoding, or no closing delimiter — which
 * is also what a truncated body looks like.
 *
 * Each part keeps its raw header block and content, so rebuild() returns the
 * original bytes exactly for every part that was not replaced.
 */
final class Multipart
{
    /**
     * @param list<array{headers: string, content: string, name: string, filename: string|null, type: string|null}> $parts
     */
    private function __construct(
        private readonly string $delimiter,
        private readonly string $close,
        public readonly array $parts,
    ) {
    }

    public static function parse(string $bytes, ?string $contentType): ?self
    {
        $boundary = self::boundary($contentType);

        if ($boundary === null) {
            return null;
        }

        $delimiter = "\r\n--" . $boundary;

        // The first delimiter has no CRLF before it; everything before it is
        // preamble, which is not allowed here.
        $chunks = explode($delimiter, "\r\n" . $bytes);

        if (count($chunks) < 3 || $chunks[0] !== '') {
            return null;
        }

        $close = (string) array_pop($chunks);

        // `--` ends the body, optionally followed by one CRLF and nothing else.
        if ($close !== '--' && $close !== "--\r\n") {
            return null;
        }

        $parts = [];

        foreach (array_slice($chunks, 1) as $chunk) {
            $part = self::part($chunk);

            if ($part === null) {
                return null;
            }

            $parts[] = $part;
        }

        return new self($delimiter, $close, $parts);
    }

    /**
     * The body with the given parts' content replaced, and every other byte
     * as it was.
     *
     * @param array<int, string> $contents Replacement content, by part index
     */
    public function rebuild(array $contents): string
    {
        $body = '';

        foreach ($this->parts as $index => $part) {
            $body .= $this->delimiter . "\r\n" . $part['headers'] . "\r\n\r\n" . ($contents[$index] ?? $part['content']);
        }

        return substr($body . $this->delimiter . $this->close, 2);
    }

    private static function boundary(?string $contentType): ?string
    {
        if ($contentType === null
            || preg_match('~;\s*boundary\s*=\s*(?:"([^"\\\\\r\n]{1,70})"|([^\s;"]{1,70}))\s*(?:;|$)~i', $contentType, $m) !== 1) {
            return null;
        }

        return $m[1] !== '' ? $m[1] : $m[2];
    }

    /**
     * @return array{headers: string, content: string, name: string, filename: string|null, type: string|null}|null
     */
    private static function part(string $chunk): ?array
    {
        if (!str_starts_with($chunk, "\r\n")) {
            return null;
        }

        $chunk = substr($chunk, 2);
        $end = strpos($chunk, "\r\n\r\n");

        if ($end === false) {
            return null;
        }

        $headers = substr($chunk, 0, $end);
        $disposition = null;
        $type = null;

        foreach (explode("\r\n", $headers) as $line) {
            $colon = strpos($line, ':');

            // A folded line or anything that is not `Name: value`.
            if ($colon === false || $colon === 0 || $line[0] === ' ' || $line[0] === "\t" || str_contains($line, "\n") || str_contains($line, "\r")) {
                return null;
            }

            $name = strtolower(trim(substr($line, 0, $colon)));
            $value = trim(substr($line, $colon + 1));

            match ($name) {
                'content-disposition' => $disposition = $value,
                'content-type' => $type = $value,
                default => null,
            };

            // Encoded content is not what the detectors would be reading.
            if ($name === 'content-transfer-encoding' && !in_array(strtolower($value), ['7bit', '8bit', 'binary'], true)) {
                return null;
            }
        }

        if ($disposition === null) {
            return null;
        }

        $params = self::dispositionParams($disposition);

        if ($params === null || !isset($params['name'])) {
            return null;
        }

        return [
            'headers' => $headers,
            'content' => substr($chunk, $end + 4),
            'name' => $params['name'],
            'filename' => $params['filename'] ?? $params['filename*'] ?? null,
            'type' => $type,
        ];
    }

    /**
     * The parameters of a `form-data` Content-Disposition, or null for any
     * other disposition or one that cannot be read.
     *
     * @return array<string, string>|null
     */
    private static function dispositionParams(string $value): ?array
    {
        if (preg_match('~^form-data\s*(;.*)?$~is', $value, $m) !== 1) {
            return null;
        }

        $rest = $m[1] ?? '';
        $params = [];

        while ($rest !== '') {
            if (preg_match('~^;\s*([^\s=;]+)\s*=\s*(?:"((?:[^"\\\\]|\\\\.)*)"|([^;\s]*))\s*~s', $rest, $p) !== 1) {
                return null;
            }

            $key = strtolower($p[1]);

            // A repeated parameter is ambiguous: which name did the server use?
            if (isset($params[$key])) {
                return null;
            }

            $params[$key] = isset($p[3]) && $p[3] !== ''
                ? $p[3]
                : (string) preg_replace('~\\\\(.)~s', '$1', $p[2] ?? '');
            $rest = substr($rest, strlen($p[0]));
        }

        return $params;
    }
}
