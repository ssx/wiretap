<?php

declare(strict_types=1);

namespace Ssx\Wiretap\Testing;

use Ssx\Wiretap\Exchange;
use Ssx\Wiretap\Export\HarExporter;

/**
 * The exchanges captured during a test or a scoped debug block.
 *
 * Immutable and filterable, so assertions read as sentences rather than as
 * array gymnastics over a raw list.
 *
 * @implements \IteratorAggregate<int, Exchange>
 */
final readonly class RecordedCalls implements \Countable, \IteratorAggregate, \JsonSerializable
{
    /**
     * @param list<Exchange> $exchanges
     */
    public function __construct(private array $exchanges = [])
    {
    }

    /**
     * @return list<Exchange>
     */
    public function all(): array
    {
        return $this->exchanges;
    }

    public function first(): ?Exchange
    {
        return $this->exchanges[0] ?? null;
    }

    public function last(): ?Exchange
    {
        return $this->exchanges === [] ? null : $this->exchanges[count($this->exchanges) - 1];
    }

    public function get(int $index): ?Exchange
    {
        return $this->exchanges[$index] ?? null;
    }

    public function isEmpty(): bool
    {
        return $this->exchanges === [];
    }

    /**
     * @param callable(Exchange): bool $matcher
     */
    public function filter(callable $matcher): self
    {
        return new self(array_values(array_filter($this->exchanges, $matcher)));
    }

    public function toHost(string $host): self
    {
        return $this->filter(static fn (Exchange $e): bool => $e->host() !== null && strcasecmp($e->host(), $host) === 0);
    }

    public function withMethod(string $method): self
    {
        return $this->filter(static fn (Exchange $e): bool => strcasecmp($e->method, $method) === 0);
    }

    public function withStatus(int $status): self
    {
        return $this->filter(static fn (Exchange $e): bool => $e->status === $status);
    }

    public function failed(): self
    {
        return $this->filter(static fn (Exchange $e): bool => $e->failed());
    }

    /**
     * Hand the whole capture to DevTools, Proxyman, Insomnia or Postman.
     *
     * Occasionally the fastest way to understand a failing integration test is
     * to look at it in the tool you would have used against production.
     */
    public function toHar(): string
    {
        return (new HarExporter())->toJson($this->exchanges);
    }

    public function count(): int
    {
        return count($this->exchanges);
    }

    public function getIterator(): \Traversable
    {
        return new \ArrayIterator($this->exchanges);
    }

    /**
     * @return list<Exchange>
     */
    public function jsonSerialize(): array
    {
        return $this->exchanges;
    }

    /**
     * A compact summary, for an assertion failure message.
     */
    public function describe(): string
    {
        if ($this->exchanges === []) {
            return '(nothing was recorded)';
        }

        $lines = [];

        foreach ($this->exchanges as $i => $exchange) {
            $lines[] = sprintf(
                '  %d. %s %s -> %s',
                $i + 1,
                $exchange->method,
                $exchange->uri,
                $exchange->error !== null
                    ? 'transport error: ' . $exchange->error->message
                    : (string) ($exchange->status ?? '?'),
            );
        }

        return implode(PHP_EOL, $lines);
    }
}
