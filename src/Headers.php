<?php

declare(strict_types=1);

namespace Ssx\Wiretap;

/**
 * An ordered header collection that preserves duplicates.
 *
 * Neither a flat map nor a name => values[] map is adequate. Set-Cookie
 * legitimately repeats, header order is occasionally meaningful when
 * debugging a signature mismatch, and the original casing is what the remote
 * end actually saw. So this keeps the wire order and does case-insensitive
 * lookup over it.
 */
final readonly class Headers implements \JsonSerializable, \Countable, \IteratorAggregate
{
    /**
     * @param list<array{0: string, 1: string}> $pairs
     */
    private function __construct(private array $pairs)
    {
    }

    public static function empty(): self
    {
        return new self([]);
    }

    /**
     * @param list<array{0: string, 1: string}> $pairs
     */
    public static function fromPairs(array $pairs): self
    {
        return new self(array_values($pairs));
    }

    /**
     * Accepts both PSR-7 shape (name => list<string>) and a flat map.
     *
     * @param array<string, string|list<string>> $map
     */
    public static function fromMap(array $map): self
    {
        $pairs = [];

        foreach ($map as $name => $value) {
            foreach ((array) $value as $single) {
                $pairs[] = [(string) $name, (string) $single];
            }
        }

        return new self($pairs);
    }

    /**
     * Parse a raw header block, as produced by CURLINFO_HEADER_OUT or
     * accumulated from CURLOPT_HEADERFUNCTION.
     *
     * The request line or status line is not a header and is skipped; callers
     * that want it should read it separately.
     */
    public static function fromRaw(string $raw): self
    {
        $pairs = [];

        foreach (preg_split('/\r\n|\r|\n/', trim($raw)) ?: [] as $line) {
            if ($line === '' || !str_contains($line, ':')) {
                continue;
            }

            [$name, $value] = explode(':', $line, 2);
            $name = trim($name);

            if ($name === '') {
                continue;
            }

            $pairs[] = [$name, trim($value)];
        }

        return new self($pairs);
    }

    /**
     * @return list<array{0: string, 1: string}>
     */
    public function pairs(): array
    {
        return $this->pairs;
    }

    public function has(string $name): bool
    {
        $needle = strtolower($name);

        foreach ($this->pairs as [$headerName]) {
            if (strtolower($headerName) === $needle) {
                return true;
            }
        }

        return false;
    }

    /**
     * @return list<string>
     */
    public function get(string $name): array
    {
        $needle = strtolower($name);
        $found = [];

        foreach ($this->pairs as [$headerName, $value]) {
            if (strtolower($headerName) === $needle) {
                $found[] = $value;
            }
        }

        return $found;
    }

    public function first(string $name): ?string
    {
        return $this->get($name)[0] ?? null;
    }

    /**
     * Rewrite every value through a callback, preserving name and order.
     *
     * @param callable(string $name, string $value): string $mapper
     */
    public function map(callable $mapper): self
    {
        $mapped = [];

        foreach ($this->pairs as [$name, $value]) {
            $mapped[] = [$name, $mapper($name, $value)];
        }

        return new self($mapped);
    }

    public function count(): int
    {
        return count($this->pairs);
    }

    public function getIterator(): \Traversable
    {
        return new \ArrayIterator($this->pairs);
    }

    /**
     * @return list<array{0: string, 1: string}>
     */
    public function jsonSerialize(): array
    {
        return $this->pairs;
    }
}
