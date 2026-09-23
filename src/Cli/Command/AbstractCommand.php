<?php

declare(strict_types=1);

namespace Ssx\Wiretap\Cli\Command;

use Ssx\Wiretap\Cli\Input;
use Ssx\Wiretap\Cli\Output;
use Ssx\Wiretap\Exchange;
use Ssx\Wiretap\Query\ExchangeQuery;
use Ssx\Wiretap\Reader\NdjsonReader;

abstract class AbstractCommand
{
    public function __construct(
        protected readonly NdjsonReader $reader,
        protected readonly Output $output,
        protected readonly string $path,
    ) {
    }

    abstract public function handle(Input $input): int;

    protected function queryFrom(Input $input, int $defaultLimit = 20): ExchangeQuery
    {
        $status = $input->option('status');
        $statusClass = null;

        // `--status=5xx` is the form people actually type.
        if ($status !== null && preg_match('/^([1-5])xx$/i', $status, $m) === 1) {
            $statusClass = $m[1] . 'xx';
            $status = null;
        }

        return new ExchangeQuery(
            host: $input->option('host'),
            method: $input->option('method'),
            status: $status !== null && is_numeric($status) ? (int) $status : null,
            statusClass: $statusClass,
            failedOnly: $input->flag('failed'),
            correlationId: $input->option('correlation'),
            since: $this->relativeTime($input->option('since')),
            limit: $input->integer('limit', $defaultLimit),
            offset: $input->integer('offset', 0),
        );
    }

    /**
     * Accepts `30m`, `2h`, `7d`. An absolute timestamp is rarely what someone
     * reaches for while debugging.
     */
    protected function relativeTime(?string $value): ?float
    {
        if ($value === null || $value === '') {
            return null;
        }

        if (preg_match('/^(\d+)\s*([smhd])$/i', trim($value), $m) !== 1) {
            return is_numeric($value) ? (float) $value : null;
        }

        $seconds = (int) $m[1] * match (strtolower($m[2])) {
            's' => 1,
            'm' => 60,
            'h' => 3600,
            'd' => 86400,
            default => 60,
        };

        return microtime(true) - $seconds;
    }

    protected function noResults(): int
    {
        $this->output->line($this->output->dim('No exchanges found in ' . $this->path));
        $this->output->line();
        $this->output->line($this->output->dim('If you expected some, run: ') . 'wiretap doctor');

        return 0;
    }

    protected function formatMs(?int $microseconds): string
    {
        if ($microseconds === null) {
            return '-';
        }

        return number_format($microseconds / 1000) . 'ms';
    }

    /**
     * Recorded text, safe to print. See Output::clean().
     */
    protected function safe(string $text): string
    {
        return Output::clean($text);
    }

    protected function shortUri(string $uri, int $max = 60): string
    {
        $uri = $this->safe($uri);

        return strlen($uri) <= $max ? $uri : substr($uri, 0, $max - 1) . '…';
    }

    protected function relativeAge(float $timestamp): string
    {
        $seconds = max(0, (int) (microtime(true) - $timestamp));

        return match (true) {
            $seconds < 60 => $seconds . 's ago',
            $seconds < 3600 => intdiv($seconds, 60) . 'm ago',
            $seconds < 86400 => intdiv($seconds, 3600) . 'h ago',
            default => intdiv($seconds, 86400) . 'd ago',
        };
    }

    protected function prettyBody(Exchange $exchange, bool $request): string
    {
        $body = $request ? $exchange->requestBody : $exchange->responseBody;

        if ($body->wasOmitted()) {
            return $this->output->dim('(not captured: ' . $body->omittedReason . ')');
        }

        if (!$body->isPresent()) {
            return $this->output->dim('(empty)');
        }

        $text = (string) $body->bytes;
        $decoded = json_decode($text, true);

        if (is_array($decoded)) {
            $text = (string) json_encode($decoded, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
        }

        $text = $this->safe($text);

        if ($body->truncated) {
            $text .= PHP_EOL . $this->output->dim(sprintf(
                '… truncated; full body was %s bytes',
                number_format((float) ($body->size ?? 0)),
            ));
        }

        return $text;
    }
}
