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

    /**
     * How `bytes` is written when the body is not valid UTF-8. The same name
     * and meaning as HAR's `content.encoding`.
     */
    public const ENCODING_BASE64 = 'base64';

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
            // A truncated capture with no known size stays unknown. Falling
            // back to the prefix length claimed the prefix *was* the whole
            // body, so a HAR export reported a four-byte transfer for a body
            // of unknown length.
            size: $size ?? ($truncated ? null : strlen($bytes)),
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
     * Replace the digest, or drop it.
     *
     * Used when redaction has changed the body: a digest of the original
     * plaintext must not be persisted beside the redacted text.
     */
    public function withDigest(?string $sha256): self
    {
        return new self(
            bytes: $this->bytes,
            size: $this->size,
            sha256: $sha256,
            contentType: $this->contentType,
            truncated: $this->truncated,
            omittedReason: $this->omittedReason,
        );
    }

    /**
     * Rebuild from a decoded NDJSON record.
     *
     * @param array<string, mixed> $data
     */
    public static function fromArray(array $data): self
    {
        $bytes = isset($data['bytes']) ? (string) $data['bytes'] : null;

        if ($bytes !== null && ($data['encoding'] ?? null) === self::ENCODING_BASE64) {
            $bytes = base64_decode($bytes, true);
            $bytes = $bytes === false ? null : $bytes;
        }

        return new self(
            bytes: $bytes,
            size: isset($data['size']) ? (int) $data['size'] : null,
            sha256: isset($data['sha256']) ? (string) $data['sha256'] : null,
            contentType: isset($data['content_type']) ? (string) $data['content_type'] : null,
            truncated: (bool) ($data['truncated'] ?? false),
            omittedReason: isset($data['omitted_reason']) ? (string) $data['omitted_reason'] : null,
        );
    }

    /**
     * @return array<string, mixed>
     */
    public function jsonSerialize(): array
    {
        [$bytes, $encoding] = $this->serialisedBytes() ?? [null, null];

        return array_filter([
            'bytes' => $bytes,
            'encoding' => $encoding,
            'size' => $this->size,
            'sha256' => $this->sha256,
            'content_type' => $this->contentType,
            'truncated' => $this->truncated ?: null,
            'omitted_reason' => $this->omittedReason,
        ], static fn (mixed $v): bool => $v !== null);
    }

    /**
     * Whether the stored bytes are valid UTF-8 text.
     */
    public function isUtf8(): bool
    {
        return $this->bytes === null || preg_match('//u', $this->bytes) === 1;
    }

    /**
     * The bytes as they are written to JSON, and the encoding they are
     * written in: null for text, `base64` otherwise. Null when there are no
     * bytes.
     *
     * JSON strings are Unicode, so a body in Latin-1, Shift JIS or any other
     * non-UTF-8 charset cannot be written as one without changing it. It used
     * to be written with every invalid byte replaced by U+FFFD, beside a
     * sha256 that still claimed the original — a record that was wrong and
     * said it was right. Base64 is lossless, so the digest stays true, and it
     * is the encoding HAR already defines for exactly this.
     *
     * A truncated prefix cut in the middle of a multibyte character is still
     * text. The partial character is dropped instead, so it stays readable;
     * it remains a prefix, and it is still marked truncated.
     *
     * @return array{string, string|null}|null
     */
    public function serialisedBytes(): ?array
    {
        if ($this->bytes === null) {
            return null;
        }

        if ($this->isUtf8()) {
            return [$this->bytes, null];
        }

        if ($this->truncated) {
            $text = self::withoutPartialCharacter($this->bytes);

            if ($text !== $this->bytes && preg_match('//u', $text) === 1) {
                return [$text, null];
            }
        }

        return [base64_encode($this->bytes), self::ENCODING_BASE64];
    }

    /**
     * Drop an incomplete UTF-8 sequence from the end of a string.
     */
    private static function withoutPartialCharacter(string $bytes): string
    {
        $length = strlen($bytes);

        for ($back = 1; $back <= min(3, $length); ++$back) {
            $byte = ord($bytes[$length - $back]);

            if (($byte & 0xc0) === 0x80) {
                continue;
            }

            return $byte >= 0xc0 ? substr($bytes, 0, $length - $back) : $bytes;
        }

        return $bytes;
    }
}
