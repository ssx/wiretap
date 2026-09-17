<?php

declare(strict_types=1);

namespace Ssx\Wiretap\Export;

use Ssx\Wiretap\CapturedBody;
use Ssx\Wiretap\Exchange;
use Ssx\Wiretap\Headers;

/**
 * Exports exchanges as HAR 1.2.
 *
 * This is the highest-leverage feature in the package and it is barely any
 * code. HAR is what Chrome DevTools, Firefox, Proxyman, Charles, Insomnia and
 * Postman all import, so supporting it turns every one of them into a viewer
 * for wiretap's data. Building a bespoke UI instead would buy a worse version
 * of what five mature tools already do.
 *
 * Spec: http://www.softwareishard.com/blog/har-12-spec/
 */
final readonly class HarExporter
{
    public function __construct(
        private string $creatorName = 'wiretap',
        private string $creatorVersion = '0.1.0',
    ) {
    }

    /**
     * @param iterable<Exchange> $exchanges
     *
     * @return array<string, mixed>
     */
    public function export(iterable $exchanges): array
    {
        $entries = [];

        foreach ($exchanges as $exchange) {
            $entries[] = $this->entry($exchange);
        }

        return [
            'log' => [
                'version' => '1.2',
                'creator' => [
                    'name' => $this->creatorName,
                    'version' => $this->creatorVersion,
                ],
                'entries' => $entries,
            ],
        ];
    }

    /**
     * @param iterable<Exchange> $exchanges
     */
    public function toJson(iterable $exchanges, bool $pretty = true): string
    {
        $flags = JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_INVALID_UTF8_SUBSTITUTE;

        if ($pretty) {
            $flags |= JSON_PRETTY_PRINT;
        }

        return (string) json_encode($this->export($exchanges), $flags);
    }

    /**
     * @return array<string, mixed>
     */
    private function entry(Exchange $exchange): array
    {
        $timings = $this->timings($exchange);

        return [
            'startedDateTime' => $this->iso8601($exchange->startedAt),
            'time' => $this->ms($exchange->timings->total),
            'request' => $this->request($exchange),
            'response' => $this->response($exchange),
            'cache' => new \stdClass(),
            'timings' => $timings,
            'serverIPAddress' => '',
            'connection' => '',
            // Not part of the spec, but HAR viewers display unknown keys in
            // their detail panes and this is where wiretap's own context
            // earns its keep.
            '_wiretap' => array_filter([
                'id' => $exchange->id,
                'correlation_id' => $exchange->correlationId,
                'transport' => $exchange->transport,
                'sequence' => $exchange->sequence,
                'attempt' => $exchange->attempt,
                'context' => $exchange->context ?: null,
                'error' => $exchange->error?->jsonSerialize(),
                'request_body_omitted' => $exchange->requestBody->omittedReason,
                'response_body_omitted' => $exchange->responseBody->omittedReason,
                'request_body_truncated' => $exchange->requestBody->truncated ?: null,
                'response_body_truncated' => $exchange->responseBody->truncated ?: null,
            ], static fn (mixed $v): bool => $v !== null),
        ];
    }

    /**
     * @return array<string, mixed>
     */
    private function request(Exchange $exchange): array
    {
        $entry = [
            'method' => $exchange->method,
            'url' => $exchange->uri,
            'httpVersion' => 'HTTP/1.1',
            'cookies' => [],
            'headers' => $this->headers($exchange->requestHeaders),
            'queryString' => $this->queryString($exchange->uri),
            'headersSize' => -1,
            'bodySize' => $exchange->requestBody->size ?? -1,
        ];

        if ($exchange->requestBody->isPresent()) {
            $entry['postData'] = [
                'mimeType' => $exchange->requestBody->contentType ?? 'application/octet-stream',
                'text' => (string) $exchange->requestBody->bytes,
                'params' => [],
            ];
        }

        return $entry;
    }

    /**
     * @return array<string, mixed>
     */
    private function response(Exchange $exchange): array
    {
        return [
            'status' => $exchange->status ?? 0,
            'statusText' => $exchange->reason ?? ($exchange->error !== null ? 'Transport error' : ''),
            'httpVersion' => 'HTTP/1.1',
            'cookies' => [],
            'headers' => $this->headers($exchange->responseHeaders),
            'content' => $this->content($exchange->responseBody),
            'redirectURL' => $exchange->responseHeaders->first('Location') ?? '',
            'headersSize' => -1,
            'bodySize' => $exchange->responseBody->size ?? -1,
        ];
    }

    /**
     * @return array<string, mixed>
     */
    private function content(CapturedBody $body): array
    {
        $content = [
            'size' => $body->size ?? 0,
            'mimeType' => $body->contentType ?? '',
        ];

        if ($body->isPresent()) {
            $content['text'] = (string) $body->bytes;
        }

        if ($body->wasOmitted()) {
            // HAR has a `comment` field on content, which viewers show. Better
            // than an empty body that looks like the server returned nothing.
            $content['comment'] = 'Body not captured: ' . $body->omittedReason;
        }

        if ($body->truncated) {
            $content['comment'] = 'Body truncated by wiretap; size is the full length.';
        }

        return $content;
    }

    /**
     * @return list<array{name: string, value: string}>
     */
    private function headers(Headers $headers): array
    {
        $out = [];

        foreach ($headers as [$name, $value]) {
            $out[] = ['name' => $name, 'value' => $value];
        }

        return $out;
    }

    /**
     * @return list<array{name: string, value: string}>
     */
    private function queryString(string $uri): array
    {
        $query = parse_url($uri, PHP_URL_QUERY);

        if (!is_string($query) || $query === '') {
            return [];
        }

        parse_str($query, $params);

        $out = [];

        foreach ($params as $name => $value) {
            foreach ((array) $value as $single) {
                $out[] = ['name' => (string) $name, 'value' => is_scalar($single) ? (string) $single : ''];
            }
        }

        return $out;
    }

    /**
     * HAR wants milliseconds, and -1 for anything not measured. Reporting 0
     * for an unmeasured phase would draw a misleading waterfall.
     *
     * @return array<string, float|int>
     */
    private function timings(Exchange $exchange): array
    {
        $t = $exchange->timings;

        $dns = $this->ms($t->dns);
        $connect = $t->connect !== null && $t->dns !== null
            ? $this->ms($t->connect - $t->dns)
            : -1;
        $ssl = $t->tls !== null && $t->connect !== null && $t->tls > 0
            ? $this->ms($t->tls - $t->connect)
            : -1;
        $wait = $t->ttfb !== null && $t->connect !== null
            ? $this->ms(max(0, $t->ttfb - max($t->connect, $t->tls ?? 0)))
            : -1;
        $receive = $t->total !== null && $t->ttfb !== null
            ? $this->ms(max(0, $t->total - $t->ttfb))
            : -1;

        return [
            'blocked' => -1,
            'dns' => $dns,
            'connect' => $connect,
            'ssl' => $ssl,
            'send' => 0,
            'wait' => $wait,
            'receive' => $receive,
        ];
    }

    private function ms(?int $microseconds): float|int
    {
        if ($microseconds === null) {
            return -1;
        }

        return round($microseconds / 1000, 3);
    }

    private function iso8601(float $timestamp): string
    {
        if ($timestamp <= 0) {
            $timestamp = microtime(true);
        }

        $date = \DateTimeImmutable::createFromFormat('U.u', number_format($timestamp, 6, '.', ''));

        if ($date === false) {
            $date = new \DateTimeImmutable();
        }

        return $date->setTimezone(new \DateTimeZone('UTC'))->format('Y-m-d\TH:i:s.vP');
    }
}
