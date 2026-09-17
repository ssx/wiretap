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
            reason: $overrides['reason'] ?? $this->reason,
            responseHeaders: $overrides['responseHeaders'] ?? $this->responseHeaders,
            responseBody: $overrides['responseBody'] ?? $this->responseBody,
            timings: $overrides['timings'] ?? $this->timings,
            error: $overrides['error'] ?? $this->error,
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
