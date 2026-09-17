<?php

declare(strict_types=1);

namespace Ssx\Wiretap;

/**
 * A body as wiretap managed to observe it.
 *
 * The distinction that matters here is between what was transmitted and what
 * was captured. Those are frequently not the same thing: a body may be too
 * large to store, may be binary, may be a live stream that cannot be read
 * without stealing bytes from the application, or may have been dropped by
 * the redactor's safety net. Callers need to tell those cases apart, so the
 * reason is recorded rather than represented as an empty string.
 *
 * `size` and `sha256` always describe the *full* body where they are known,
 * even when `bytes` holds only a truncated prefix. That is what makes
 * truncation tolerable: two exchanges can still be compared for identical
 * payloads, and a reader can tell whether what they are looking at is
 * complete.
 */
final readonly class CapturedBody implements \JsonSerializable
{
    public const OMITTED_BINARY = 'binary';
    public const OMITTED_NOT_READABLE = 'not-readable';
    public const OMITTED_NOT_SEEKABLE = 'not-seekable';
    public const OMITTED_NOT_RETURNED = 'not-returned';
    public const OMITTED_STREAMING = 'streaming';
    public const OMITTED_REDACTED = 'redacted';
    public const OMITTED_DISABLED = 'disabled';

    private function __construct(
        public ?string $bytes,
        public ?int $size,
        public ?string $sha256,
        public ?string $contentType,
        public bool $truncated,
        public ?string $omittedReason,
    ) {
    }

    /**
     * A body that was captured, in whole or in part.
     *
     * @param string   $bytes       What we stored, which may be a prefix
     * @param int|null $size        Full size where known; null for unknown-length streams
     * @param bool     $truncated   Whether $bytes is a prefix of the full body
     */
    public static function captured(
        string $bytes,
        ?int $size = null,
        ?string $contentType = null,
        bool $truncated = false,
        ?string $sha256 = null,
    ): self {
        return new self(
            bytes: $bytes,
            size: $size ?? strlen($bytes),
            sha256: $sha256,
            contentType: $contentType,
            truncated: $truncated,
            omittedReason: null,
        );
    }

    /**
     * A body that exists but was deliberately not stored.
     */
    public static function omitted(
        string $reason,
        ?int $size = null,
        ?string $contentType = null,
        ?string $sha256 = null,
    ): self {
        return new self(
            bytes: null,
            size: $size,
            sha256: $sha256,
            contentType: $contentType,
            truncated: false,
            omittedReason: $reason,
        );
    }

    /**
     * No body was present at all — a GET request, a 204 response.
     */
    public static function none(): self
    {
        return new self(
            bytes: null,
            size: 0,
            sha256: null,
            contentType: null,
            truncated: false,
            omittedReason: null,
        );
    }

    public function isPresent(): bool
    {
        return $this->bytes !== null;
    }

    public function wasOmitted(): bool
    {
        return $this->omittedReason !== null;
    }

    /**
     * Replace the stored bytes, keeping the full-body metadata intact.
     *
     * Used by the redactor, which rewrites content without changing what we
     * know about the original.
     */
    public function withBytes(string $bytes, ?bool $truncated = null): self
    {
        return new self(
            bytes: $bytes,
            size: $this->size,
            sha256: $this->sha256,
            contentType: $this->contentType,
            truncated: $truncated ?? $this->truncated,
            omittedReason: null,
        );
    }

    /**
     * @return array<string, mixed>
     */
    public function jsonSerialize(): array
    {
        return array_filter([
            'bytes' => $this->bytes,
            'size' => $this->size,
            'sha256' => $this->sha256,
            'content_type' => $this->contentType,
            'truncated' => $this->truncated ?: null,
            'omitted_reason' => $this->omittedReason,
        ], static fn (mixed $v): bool => $v !== null);
    }
}
