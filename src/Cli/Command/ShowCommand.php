<?php

declare(strict_types=1);

namespace Ssx\Wiretap\Cli\Command;

use Ssx\Wiretap\Cli\Input;
use Ssx\Wiretap\Cli\Output;
use Ssx\Wiretap\Exchange;
use Ssx\Wiretap\Export\HarExporter;

final class ShowCommand extends AbstractCommand
{
    public function handle(Input $input): int
    {
        $target = $input->argument(0);

        if ($target === null) {
            $this->output->line($this->output->red('Which one? Try: wiretap show 1'));

            return 1;
        }

        $exchange = $this->resolve($target, $input);

        if ($exchange === null) {
            $this->output->line($this->output->red("No exchange matching '{$target}'."));

            return 1;
        }

        if ($input->flag('curl')) {
            $this->output->line($this->safe($this->toCurl($exchange)));

            return 0;
        }

        if ($input->flag('har')) {
            $this->output->line(Output::cleanJson((new HarExporter())->toJson([$exchange])));

            return 0;
        }

        if ($input->flag('json')) {
            $this->output->line((string) json_encode($exchange, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES));

            return 0;
        }

        $this->render($exchange, $input->flag('raw'));

        return 0;
    }

    private function resolve(string $target, Input $input): ?Exchange
    {
        // A bare number means "the nth row of the listing I just looked at",
        // which is how people actually refer to these.
        if (ctype_digit($target)) {
            return $this->reader->findByPosition((int) $target, $this->queryFrom($input, 100));
        }

        return $this->reader->find($target);
    }

    private function render(Exchange $exchange, bool $raw): void
    {
        $o = $this->output;

        $o->line();
        $o->line($o->bold($this->safe($exchange->method) . ' ') . $this->safe($exchange->uri));
        $o->line($o->dim(sprintf(
            '  %s · %s · %s · id %s',
            $o->statusColour($exchange->status),
            $this->formatMs($exchange->timings->total),
            $this->relativeAge($exchange->startedAt),
            $this->safe($exchange->id),
        )));

        if ($exchange->context !== []) {
            $pairs = [];

            foreach ($exchange->context as $key => $value) {
                if ($value !== null && $value !== '') {
                    $pairs[] = $this->safe($key . '=' . $value);
                }
            }

            if ($pairs !== []) {
                $o->line($o->dim('  ' . implode(' · ', $pairs)));
            }
        }

        if ($exchange->error !== null) {
            $o->line('  ' . $o->red(sprintf('transport error %d: %s', $exchange->error->errno, $this->safe($exchange->error->message))));
        }

        $this->renderTimings($exchange);

        $o->line();
        $o->line($o->cyan('REQUEST'));
        $this->renderHeaders($exchange, true);
        $o->line();
        $o->line($raw ? $this->safe((string) $exchange->requestBody->bytes) : $this->prettyBody($exchange, true));

        $o->line();
        $o->line($o->cyan('RESPONSE'));
        $this->renderHeaders($exchange, false);
        $o->line();
        $o->line($raw ? $this->safe((string) $exchange->responseBody->bytes) : $this->prettyBody($exchange, false));
        $o->line();
        $correlation = $this->safe($exchange->correlationId);
        $o->line($o->dim('  correlation ' . $correlation . '  ·  wiretap trace ' . $correlation));
        $o->line();
    }

    private function renderHeaders(Exchange $exchange, bool $request): void
    {
        $headers = $request ? $exchange->requestHeaders : $exchange->responseHeaders;
        $marker = $request ? '>' : '<';

        if ($headers->count() === 0) {
            $this->output->line($this->output->dim("  {$marker} (no headers captured)"));

            return;
        }

        foreach ($headers as [$name, $value]) {
            $this->output->line(sprintf('  %s %s: %s', $this->output->dim($marker), $this->output->bold($this->safe($name)), $this->safe($value)));
        }
    }

    private function renderTimings(Exchange $exchange): void
    {
        $t = $exchange->timings;

        if ($t->total === null) {
            return;
        }

        $parts = [];

        foreach (['dns' => $t->dns, 'connect' => $t->connect, 'tls' => $t->tls, 'ttfb' => $t->ttfb, 'total' => $t->total] as $label => $value) {
            if ($value !== null && $value > 0) {
                $parts[] = $label . ' ' . $this->formatMs($value);
            }
        }

        if ($parts !== []) {
            $this->output->line($this->output->dim('  ' . implode(' · ', $parts)));
        }
    }

    /**
     * Rebuild an equivalent curl command.
     *
     * Secrets were removed at capture, so this is reproducible in shape rather
     * than runnable as-is against an authenticated endpoint. That is the
     * correct trade: a runnable command would mean the log held the token.
     */
    private function toCurl(Exchange $exchange): string
    {
        $parts = ['curl', '-X ' . escapeshellarg($exchange->method)];

        foreach ($exchange->requestHeaders as [$name, $value]) {
            if (strcasecmp($name, 'host') === 0 || strcasecmp($name, 'content-length') === 0) {
                continue;
            }

            $parts[] = '-H ' . escapeshellarg($name . ': ' . $value);
        }

        if ($exchange->requestBody->isPresent()) {
            $parts[] = '--data ' . escapeshellarg((string) $exchange->requestBody->bytes);
        }

        $parts[] = escapeshellarg($exchange->uri);

        return implode(" \\\n  ", $parts);
    }
}
