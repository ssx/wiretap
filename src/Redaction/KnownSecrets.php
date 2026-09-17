<?php

declare(strict_types=1);

namespace Ssx\Wiretap\Redaction;

/**
 * Values already established as secret within one exchange.
 *
 * A structural rule can only remove what it can name. When an API echoes its
 * input back — and a great many do, from httpbin to most REST endpoints that
 * return the created resource — a token stripped from the query string
 * reappears verbatim in the response body, where no header rule, path rule or
 * regex is looking for it.
 *
 * So anything removed from the URL or the headers is remembered, and the same
 * literal is swept out of every body in the same exchange.
 *
 * Short values are ignored deliberately. Redacting every occurrence of a
 * three-character token would corrupt unrelated content and make the log
 * useless, which is the failure mode that gets redaction switched off.
 */
final class KnownSecrets
{
    /** @var array<string, true> */
    private array $values = [];

    /**
     * Values that must never be treated as secret, however they arrive.
     *
     * The exchange's own host is the case that matters: a Set-Cookie carrying
     * `Domain=api.example.com` made the host a "secret", and the record then
     * described a request to `https://[REDACTED]` — breaking `list --host`,
     * toHost() and alwaysHosts sampling, in a tool whose job is to say what
     * happened.
     *
     * @var array<string, true>
     */
    private array $protected = [];

    public function __construct(private readonly int $minLength = 8)
    {
    }

    /**
     * Mark a value as never-secret. Call before remembering anything.
     */
    public function protect(string $value): void
    {
        $value = trim($value);

        if ($value !== '') {
            $this->protected[$value] = true;
        }
    }

    public function remember(string $value): void
    {
        $value = trim($value);

        if (strlen($value) < $this->minLength || isset($this->protected[$value])) {
            return;
        }

        $this->values[$value] = true;

        // The same value appears in other encodings depending on where it is
        // echoed back, and a literal comparison misses every one of them.
        foreach ($this->encodingsOf($value) as $variant) {
            if ($variant !== $value
                && strlen($variant) >= $this->minLength
                && !isset($this->protected[$variant])) {
                $this->values[$variant] = true;
            }
        }
    }

    /**
     * Pull the credential out of a scheme-prefixed header value.
     *
     * `Authorization: Bearer abc123` should also register `abc123`, because
     * that is the part an API echoes back, without the scheme.
     */
    public function rememberCredentialValue(string $headerValue): void
    {
        $parts = preg_split('/\s+/', trim($headerValue), 2);

        if ($parts !== false && count($parts) === 2) {
            $this->remember($parts[1]);
        }

        // Basic auth carries the credential base64-encoded; the decoded form
        // is what shows up elsewhere.
        if (stripos($headerValue, 'basic ') === 0) {
            $decoded = base64_decode(trim(substr($headerValue, 6)), true);

            if (is_string($decoded) && $decoded !== '') {
                $this->remember($decoded);

                foreach (explode(':', $decoded, 2) as $part) {
                    $this->remember($part);
                }
            }
        }
    }

    /**
     * Remember each cookie's value separately.
     *
     * `Cookie: session=abc; theme=dark` is remembered whole, so a response
     * echoing just `abc` was not recognised. Individual values are what get
     * echoed back.
     */
    public function rememberCookieValues(string $headerValue): void
    {
        // Only the first pair. Everything after the first semicolon is
        // attributes — Domain, Path, Expires, SameSite — and treating those as
        // secrets meant a response that set a cookie scoped to its own domain
        // redacted that domain out of its own record.
        $first = explode(';', $headerValue, 2)[0];
        $parts = explode('=', trim($first), 2);

        if (count($parts) === 2) {
            $this->remember(trim($parts[1], " \t\"'"));
        }
    }

    /**
     * @return list<string>
     */
    private function encodingsOf(string $value): array
    {
        $variants = [rawurlencode($value), urlencode($value)];

        // JSON escaping is the one that bit us: a token containing a slash is
        // written as abc\/def inside a serialised body, so scrubbing the raw
        // form found nothing. Trimming the quotes json_encode adds leaves the
        // escaped body text.
        $json = json_encode($value);

        if (is_string($json) && strlen($json) > 2) {
            $variants[] = substr($json, 1, -1);
        }

        return array_values(array_unique(array_filter(
            $variants,
            static fn (string $v): bool => $v !== '',
        )));
    }

    public function scrub(string $subject, string $replacement): string
    {
        if ($this->values === [] || $subject === '') {
            return $subject;
        }

        $values = array_keys($this->values);

        // Longest first. str_replace applies its search list in order, so a
        // shorter secret that is a prefix of a longer one would otherwise
        // replace the prefix and leave the remainder of the longer secret in
        // place — turning `abcdefghSECRETTAIL` into `[REDACTED]SECRETTAIL`.
        usort($values, static fn (string $a, string $b): int => strlen($b) <=> strlen($a));

        return str_replace($values, $replacement, $subject);
    }

    public function isEmpty(): bool
    {
        return $this->values === [];
    }

    public function count(): int
    {
        return count($this->values);
    }
}
