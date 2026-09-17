<?php

declare(strict_types=1);

namespace Ssx\Wiretap;

/**
 * One outbound HTTP call, as observed.
 *
 * Immutable by construction. The capture layers build one of these and hand
 * it to a sink; nothing downstream mutates it, which is what lets the same
 * record be written to several sinks without defensive copying.
 */
final readonly class Exchange implements \JsonSerializable
{
    public const TRANSPORT_CURL = 'curl';
    public const TRANSPORT_GUZZLE = 'guzzle';
    public const TRANSPORT_PSR18 = 'psr18';

    /**
     * @param array<string, scalar|null> $context
     * @param list<string>               $tags
     */
    public function __construct(
        public string $id,
        public string $correlationId,
        public string $transport,
        public string $method,
        public string $uri,
        public Headers $requestHeaders,
        public CapturedBody $requestBody,
        public ?int $status,
        public ?string $reason,
        public Headers $responseHeaders,
        public CapturedBody $responseBody,
        public Timings $timings,
        public ?TransferError $error,
        public float $startedAt,
        public ?string $parentExchangeId = null,
        public int $sequence = 0,
        public int $attempt = 1,
        public array $context = [],
        public array $tags = [],
        public ?int $pid = null,
        public ?string $hostname = null,
    ) {
    }

    public function host(): ?string
    {
        $host = parse_url($this->uri, PHP_URL_HOST);

        return is_string($host) ? $host : null;
    }

    public function scheme(): ?string
    {
        $scheme = parse_url($this->uri, PHP_URL_SCHEME);

        return is_string($scheme) ? $scheme : null;
    }

    public function path(): ?string
    {
        $path = parse_url($this->uri, PHP_URL_PATH);

        return is_string($path) ? $path : null;
    }

    public function failed(): bool
    {
        return $this->error !== null || ($this->status !== null && $this->status >= 400);
    }

    public function withRequestHeaders(Headers $headers): self
    {
        return $this->with(requestHeaders: $headers);
    }

    public function withResponseHeaders(Headers $headers): self
    {
        return $this->with(responseHeaders: $headers);
    }

    public function withRequestBody(CapturedBody $body): self
    {
        return $this->with(requestBody: $body);
    }

    public function withResponseBody(CapturedBody $body): self
    {
        return $this->with(responseBody: $body);
    }

    public function withUri(string $uri): self
    {
        return $this->with(uri: $uri);
    }

    public function withError(?TransferError $error): self
    {
        return $this->with(error: $error);
    }

    public function withReason(?string $reason): self
    {
        return $this->with(reason: $reason);
    }

    /**
     * @param list<string> $tags
     */
    public function withTags(array $tags): self
    {
        return $this->with(tags: $tags);
    }

    /**
     * @param array<string, scalar|null> $context
     */
    public function withContext(array $context): self
    {
        return $this->with(context: [...$this->context, ...$context]);
    }

    private function with(mixed ...$overrides): self
    {
        return new self(
            id: $overrides['id'] ?? $this->id,
            correlationId: $overrides['correlationId'] ?? $this->correlationId,
            transport: $overrides['transport'] ?? $this->transport,
            method: $overrides['method'] ?? $this->method,
            uri: $overrides['uri'] ?? $this->uri,
            requestHeaders: $overrides['requestHeaders'] ?? $this->requestHeaders,
            requestBody: $overrides['requestBody'] ?? $this->requestBody,
            status: $overrides['status'] ?? $this->status,
            reason: array_key_exists('reason', $overrides) ? $overrides['reason'] : $this->reason,
            responseHeaders: $overrides['responseHeaders'] ?? $this->responseHeaders,
            responseBody: $overrides['responseBody'] ?? $this->responseBody,
            timings: $overrides['timings'] ?? $this->timings,
            error: array_key_exists('error', $overrides) ? $overrides['error'] : $this->error,
            startedAt: $overrides['startedAt'] ?? $this->startedAt,
            parentExchangeId: $overrides['parentExchangeId'] ?? $this->parentExchangeId,
            sequence: $overrides['sequence'] ?? $this->sequence,
            attempt: $overrides['attempt'] ?? $this->attempt,
            context: $overrides['context'] ?? $this->context,
            tags: $overrides['tags'] ?? $this->tags,
            pid: $overrides['pid'] ?? $this->pid,
            hostname: $overrides['hostname'] ?? $this->hostname,
        );
    }

    /**
     * Rebuild from one decoded NDJSON line.
     *
     * Tolerant by design: a log file written by an older version, or one
     * truncated mid-write, should still yield everything that survived rather
     * than throwing and taking the whole listing with it.
     *
     * @param array<string, mixed> $data
     */
    public static function fromArray(array $data): self
    {
        /** @var array<string, mixed> $request */
        $request = is_array($data['request'] ?? null) ? $data['request'] : [];
        /** @var array<string, mixed> $response */
        $response = is_array($data['response'] ?? null) ? $data['response'] : [];

        $headers = static function (mixed $pairs): Headers {
            if (!is_array($pairs)) {
                return Headers::empty();
            }

            /** @var list<array{0: string, 1: string}> $pairs */
            return Headers::fromPairs($pairs);
        };

        $body = static fn (mixed $b): CapturedBody => is_array($b)
            ? CapturedBody::fromArray($b)
            : CapturedBody::none();

        return new self(
            id: (string) ($data['id'] ?? ''),
            correlationId: (string) ($data['correlation_id'] ?? ''),
            transport: (string) ($data['transport'] ?? self::TRANSPORT_CURL),
            method: (string) ($data['method'] ?? 'GET'),
            uri: (string) ($data['uri'] ?? ''),
            requestHeaders: $headers($request['headers'] ?? null),
            requestBody: $body($request['body'] ?? null),
            status: isset($data['status']) ? (int) $data['status'] : null,
            reason: isset($data['reason']) ? (string) $data['reason'] : null,
            responseHeaders: $headers($response['headers'] ?? null),
            responseBody: $body($response['body'] ?? null),
            timings: is_array($data['timings'] ?? null) ? Timings::fromArray($data['timings']) : new Timings(),
            error: is_array($data['error'] ?? null) ? TransferError::fromArray($data['error']) : null,
            startedAt: (float) ($data['started_at'] ?? 0.0),
            parentExchangeId: isset($data['parent_exchange_id']) ? (string) $data['parent_exchange_id'] : null,
            sequence: (int) ($data['sequence'] ?? 0),
            attempt: (int) ($data['attempt'] ?? 1),
            context: is_array($data['context'] ?? null) ? $data['context'] : [],
            tags: is_array($data['tags'] ?? null) ? array_values($data['tags']) : [],
            pid: isset($data['pid']) ? (int) $data['pid'] : null,
            hostname: isset($data['hostname']) ? (string) $data['hostname'] : null,
        );
    }

    /**
     * @return array<string, mixed>
     */
    public function jsonSerialize(): array
    {
        return array_filter([
            'id' => $this->id,
            'correlation_id' => $this->correlationId,
            'parent_exchange_id' => $this->parentExchangeId,
            'sequence' => $this->sequence,
            'attempt' => $this->attempt,
            'transport' => $this->transport,
            'method' => $this->method,
            'uri' => $this->uri,
            'host' => $this->host(),
            'request' => [
                'headers' => $this->requestHeaders,
                'body' => $this->requestBody,
            ],
            'status' => $this->status,
            'reason' => $this->reason,
            'response' => [
                'headers' => $this->responseHeaders,
                'body' => $this->responseBody,
            ],
            'timings' => $this->timings,
            'error' => $this->error,
            'started_at' => $this->startedAt,
            'pid' => $this->pid,
            'hostname' => $this->hostname,
            'context' => $this->context ?: null,
            'tags' => $this->tags ?: null,
        ], static fn (mixed $v): bool => $v !== null);
    }
}
