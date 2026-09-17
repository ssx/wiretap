<?php

declare(strict_types=1);

namespace Ssx\Wiretap;

/**
 * A transport-level failure: DNS resolution, connection refused, TLS
 * handshake, timeout. Distinct from an HTTP error response, which is a
 * successful exchange carrying a 4xx or 5xx status.
 */
final readonly class TransferError implements \JsonSerializable
{
    public function __construct(
        public int $errno,
        public string $message,
        public ?string $class = null,
    ) {
    }

    public static function fromThrowable(\Throwable $e): self
    {
        return new self(
            errno: $e->getCode() === 0 ? -1 : (int) $e->getCode(),
            message: $e->getMessage(),
            class: $e::class,
        );
    }

    /**
     * @return array<string, mixed>
     */
    public function jsonSerialize(): array
    {
        return array_filter([
            'errno' => $this->errno,
            'message' => $this->message,
            'class' => $this->class,
        ], static fn (mixed $v): bool => $v !== null);
    }
}
