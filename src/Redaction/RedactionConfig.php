<?php

declare(strict_types=1);

namespace Ssx\Wiretap\Redaction;

/**
 * What the redactor removes, and how.
 *
 * Defaults are deliberately protective. Someone who installs wiretap to chase
 * a bug should not have to think about secrets before their first capture.
 */
final readonly class RedactionConfig
{
    public const MODE_DENY = 'deny';
    public const MODE_ALLOW = 'allow';

    /**
     * Headers redacted by default. Case-insensitive.
     *
     * @var list<string>
     */
    public const DEFAULT_HEADERS = [
        'authorization',
        'proxy-authorization',
        'cookie',
        'set-cookie',
        'x-api-key',
        'api-key',
        'apikey',
        'x-auth-token',
        'x-authorization',
        'x-amz-security-token',
        'x-shopify-access-token',
        'x-csrf-token',
        'x-xsrf-token',
        'signature',
        'x-signature',
        'x-hub-signature',
        'x-hub-signature-256',
    ];

    /**
     * Query parameters redacted by default. The URL is the single most
     * commonly forgotten place for a secret to leak.
     *
     * @var list<string>
     */
    public const DEFAULT_QUERY = [
        'api_key',
        'apikey',
        'token',
        'access_token',
        'refresh_token',
        'id_token',
        'auth',
        'signature',
        'sig',
        'key',
        'secret',
        'password',
        'passwd',
        'pwd',
    ];

    /**
     * Content types whose bodies are worth capturing. Everything else is
     * recorded as size and hash only — the single highest-leverage rule in
     * the pipeline, because it solves memory, disk and most accidental
     * exposure at once.
     *
     * @var list<string>
     */
    public const DEFAULT_CAPTURABLE_TYPES = [
        'application/json',
        'application/xml',
        'text/xml',
        'application/x-www-form-urlencoded',
        'application/graphql',
        'application/x-ndjson',
        'text/',
    ];

    /**
     * @param list<string>              $headers    Header names, matched case-insensitively
     * @param list<string>              $query      Query parameter names
     * @param list<string>              $bodyPaths  Dot paths with `*` wildcards, e.g. `card.number`, `payment.*.token`
     * @param array<string, bool>       $patterns   Built-in regex detectors, by name
     * @param list<string>              $custom     Extra regexes, applied as-is
     * @param list<string>              $capturableTypes
     */
    public function __construct(
        public bool $enabled = true,
        public string $headerMode = self::MODE_DENY,
        public array $headers = self::DEFAULT_HEADERS,
        public array $query = self::DEFAULT_QUERY,
        public array $bodyPaths = [],
        public array $patterns = [
            'pan' => true,
            'bearer' => true,
            'jwt' => true,
            'aws_key' => true,
            'stripe_key' => true,
            'email' => false,
        ],
        public array $custom = [],
        public string $replacement = '[REDACTED]',
        public bool $hashHint = false,
        public ?string $hashSalt = null,
        public bool $safetyNet = true,
        public array $capturableTypes = self::DEFAULT_CAPTURABLE_TYPES,
        public int $maxBodyBytes = 65536,
        public int $maxHeaderValueBytes = 4096,
        public int $minEchoedSecretLength = 8,
        public bool $omitUninspectableBodies = true,
    ) {
        // A hint keyed with an empty string is a public function of the
        // plaintext. Two million candidates took under four seconds, so a
        // known card BIN falls in about half an hour on one core — and the
        // hint sits in the log beside the value it was meant to protect.
        if ($this->hashHint && ($this->hashSalt ?? '') === '') {
            throw new \InvalidArgumentException(
                'Redaction hash hints need a hashSalt. Without one the hint is an '
                . 'unkeyed hash of the plaintext and can be reversed offline. Set '
                . 'hashSalt to a per-install secret, or leave hashHint off.'
            );
        }
    }

    public function isCapturableType(?string $contentType): bool
    {
        if ($contentType === null || $contentType === '') {
            // No content type and a non-empty body is usually a badly behaved
            // API rather than binary. Capture it; the safety net still runs.
            return true;
        }

        $type = strtolower(trim(explode(';', $contentType)[0]));

        foreach ($this->capturableTypes as $allowed) {
            if (str_starts_with($type, strtolower($allowed))) {
                return true;
            }
        }

        // RFC 6839 structured syntax suffixes. Listing individual vendor
        // types could never keep up: application/vnd.api+json,
        // application/hal+json and application/vnd.github+json were all
        // recorded as binary and dropped, because only two of the dozens of
        // +json types in use happened to be in the list.
        foreach (['+json', '+xml'] as $suffix) {
            if (str_ends_with($type, $suffix)) {
                return true;
            }
        }

        return false;
    }

    public function disabled(): self
    {
        return new self(
            enabled: false,
            headerMode: $this->headerMode,
            headers: $this->headers,
            query: $this->query,
            bodyPaths: $this->bodyPaths,
            patterns: $this->patterns,
            custom: $this->custom,
            replacement: $this->replacement,
            hashHint: $this->hashHint,
            hashSalt: $this->hashSalt,
            safetyNet: $this->safetyNet,
            capturableTypes: $this->capturableTypes,
            maxBodyBytes: $this->maxBodyBytes,
            maxHeaderValueBytes: $this->maxHeaderValueBytes,
            minEchoedSecretLength: $this->minEchoedSecretLength,
            omitUninspectableBodies: $this->omitUninspectableBodies,
        );
    }
}
