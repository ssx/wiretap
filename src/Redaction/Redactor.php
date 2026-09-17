<?php

declare(strict_types=1);

namespace Ssx\Wiretap\Redaction;

use Ssx\Wiretap\CapturedBody;
use Ssx\Wiretap\Exchange;
use Ssx\Wiretap\Headers;
use Ssx\Wiretap\Support\Regex;

/**
 * Removes secrets from an exchange before it is ever persisted.
 *
 * Redaction happens at capture, not at display. Once plaintext reaches disk
 * or a database it is in scope: backups contain it, `SELECT *` leaks it,
 * staging dumps carry it onto laptops, and a rendering bug becomes a breach.
 *
 * The layers run in a fixed order and the order is not cosmetic:
 *
 *   1. content-type gate     binary never captured
 *   2. URL query parameters  the most commonly forgotten leak
 *   3. headers               denylist, or allowlist in strict mode
 *   4. structured body paths dot paths over decoded JSON
 *   5. regex detectors       PAN (Luhn-checked), bearer, JWT, API keys
 *   6. safety net            re-scan the result; drop the body on a hit
 *
 * Truncation happens *after* redaction, never before. Truncating first can
 * split a card number across the boundary, leaving eleven digits in the store
 * that no detector will ever match again.
 */
final readonly class Redactor
{
    public function __construct(private RedactionConfig $config = new RedactionConfig())
    {
    }

    public function redact(Exchange $exchange): Exchange
    {
        if (!$this->config->enabled) {
            return $exchange;
        }

        return $exchange
            ->withUri($this->redactUrl($exchange->uri))
            ->withRequestHeaders($this->redactHeaders($exchange->requestHeaders))
            ->withResponseHeaders($this->redactHeaders($exchange->responseHeaders))
            ->withRequestBody($this->redactBody($exchange->requestBody))
            ->withResponseBody($this->redactBody($exchange->responseBody));
    }

    /**
     * Layer 2. Rewrites the query string properly rather than regexing the
     * whole URL, so a parameter value that happens to contain an ampersand
     * cannot smuggle plaintext through.
     */
    public function redactUrl(string $url): string
    {
        $parts = parse_url($url);

        if ($parts === false) {
            return $url;
        }

        $hasQuery = isset($parts['query']) && $parts['query'] !== '';

        // Credentials in userinfo leak just as readily as ones in the query
        // string, and a URL carrying them frequently has no query string at
        // all — so this cannot short-circuit on the query alone.
        if (!$hasQuery && !isset($parts['user'])) {
            return $url;
        }

        $query = '';

        if ($hasQuery) {
            parse_str((string) $parts['query'], $params);
            $query = http_build_query($this->redactQueryParams($params), '', '&', PHP_QUERY_RFC3986);
        }

        return $this->rebuildUrl($parts, $query);
    }

    /**
     * @param array<array-key, mixed> $params
     *
     * @return array<array-key, mixed>
     */
    private function redactQueryParams(array $params): array
    {
        foreach ($params as $name => $value) {
            if (is_array($value)) {
                /** @var array<array-key, mixed> $value */
                $params[$name] = $this->redactQueryParams($value);

                continue;
            }

            if ($this->isSensitiveQueryParam((string) $name)) {
                $params[$name] = $this->replacementFor(is_scalar($value) ? (string) $value : '');
            }
        }

        return $params;
    }

    private function isSensitiveQueryParam(string $name): bool
    {
        $name = strtolower($name);

        foreach ($this->config->query as $sensitive) {
            if ($name === strtolower($sensitive)) {
                return true;
            }
        }

        return false;
    }

    /**
     * @param array<string, int|string> $parts
     */
    private function rebuildUrl(array $parts, string $query): string
    {
        $url = '';

        if (isset($parts['scheme'])) {
            $url .= $parts['scheme'] . '://';
        }

        // Credentials in userinfo are secrets by definition.
        if (isset($parts['user'])) {
            $url .= $this->config->replacement;
            $url .= isset($parts['pass']) ? ':' . $this->config->replacement : '';
            $url .= '@';
        }

        $url .= $parts['host'] ?? '';
        $url .= isset($parts['port']) ? ':' . $parts['port'] : '';
        $url .= $parts['path'] ?? '';
        $url .= $query !== '' ? '?' . $query : '';
        $url .= isset($parts['fragment']) ? '#' . $parts['fragment'] : '';

        return $url;
    }

    /**
     * Layer 3. Denylist by default; allowlist for regulated deployments,
     * where anything not explicitly permitted is removed.
     */
    public function redactHeaders(Headers $headers): Headers
    {
        return $headers->map(function (string $name, string $value): string {
            if ($this->isSensitiveHeader($name)) {
                return $this->replacementFor($value);
            }

            // Long header values are almost always tokens or serialised
            // state. Cap them before they reach the store.
            if (strlen($value) > $this->config->maxHeaderValueBytes) {
                $value = substr($value, 0, $this->config->maxHeaderValueBytes) . '…[truncated]';
            }

            return $this->applyPatterns($value);
        });
    }

    private function isSensitiveHeader(string $name): bool
    {
        $name = strtolower($name);
        $listed = false;

        foreach ($this->config->headers as $candidate) {
            if ($name === strtolower($candidate)) {
                $listed = true;

                break;
            }
        }

        return $this->config->headerMode === RedactionConfig::MODE_ALLOW
            ? !$listed
            : $listed;
    }

    /**
     * Layers 1, 4, 5 and 6.
     */
    public function redactBody(CapturedBody $body): CapturedBody
    {
        if (!$body->isPresent()) {
            return $body;
        }

        // Layer 1.
        if (!$this->config->isCapturableType($body->contentType)) {
            return CapturedBody::omitted(
                CapturedBody::OMITTED_BINARY,
                $body->size,
                $body->contentType,
                $body->sha256,
            );
        }

        $bytes = (string) $body->bytes;

        // Layer 4, then 5.
        $bytes = $this->redactStructured($bytes, $body->contentType);
        $bytes = $this->applyPatterns($bytes);

        // Layer 6. A mis-scoped path rule should not be able to become an
        // incident, so the finished value is scanned once more and the whole
        // body dropped if anything survived.
        if ($this->config->safetyNet && $this->containsLikelySecret($bytes)) {
            return CapturedBody::omitted(
                CapturedBody::OMITTED_REDACTED,
                $body->size,
                $body->contentType,
                $body->sha256,
            );
        }

        // Truncation is last, deliberately.
        $truncated = $body->truncated;

        if (strlen($bytes) > $this->config->maxBodyBytes) {
            $bytes = substr($bytes, 0, $this->config->maxBodyBytes);
            $truncated = true;
        }

        return $body->withBytes($bytes, $truncated);
    }

    /**
     * Layer 4. Dot paths with `*` wildcards over decoded JSON or form data,
     * never regex over the raw text — a regex cannot tell a key from a value
     * and will happily redact the wrong half.
     */
    private function redactStructured(string $bytes, ?string $contentType): string
    {
        if ($this->config->bodyPaths === []) {
            return $bytes;
        }

        $type = strtolower(explode(';', $contentType ?? '')[0]);

        if (str_contains($type, 'x-www-form-urlencoded')) {
            parse_str($bytes, $form);
            $form = $this->redactPaths($form, $this->config->bodyPaths);

            return http_build_query($form, '', '&', PHP_QUERY_RFC3986);
        }

        $decoded = json_decode($bytes, true);

        if (!is_array($decoded)) {
            // Not JSON, or malformed, or a truncated prefix. Fall through to
            // the regex layer rather than persisting a raw prefix we could
            // not inspect structurally.
            return $bytes;
        }

        $redacted = $this->redactPaths($decoded, $this->config->bodyPaths);
        $encoded = json_encode($redacted, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);

        return $encoded === false ? $bytes : $encoded;
    }

    /**
     * @param array<array-key, mixed> $data
     * @param list<string>            $paths
     *
     * @return array<array-key, mixed>
     */
    private function redactPaths(array $data, array $paths): array
    {
        foreach ($paths as $path) {
            $data = $this->redactPath($data, explode('.', $path));
        }

        return $data;
    }

    /**
     * @param array<array-key, mixed> $data
     * @param list<string>            $segments
     *
     * @return array<array-key, mixed>
     */
    private function redactPath(array $data, array $segments): array
    {
        if ($segments === []) {
            return $data;
        }

        $segment = array_shift($segments);
        $keys = $segment === '*' ? array_keys($data) : [$segment];

        foreach ($keys as $key) {
            if (!array_key_exists($key, $data)) {
                continue;
            }

            if ($segments === []) {
                $value = $data[$key];
                $data[$key] = $this->replacementFor(is_scalar($value) ? (string) $value : '');

                continue;
            }

            if (is_array($data[$key])) {
                /** @var array<array-key, mixed> $child */
                $child = $data[$key];
                $data[$key] = $this->redactPath($child, $segments);
            }
        }

        return $data;
    }

    /**
     * Layer 5.
     */
    public function applyPatterns(string $value): string
    {
        foreach (Patterns::all() as $name => $regex) {
            if (($this->config->patterns[$name] ?? false) !== true) {
                continue;
            }

            $value = $name === 'pan'
                ? $this->redactPans($value)
                : (preg_replace_callback(
                    $regex,
                    fn (array $m): string => $this->replacementFor($m[0]),
                    $value,
                ) ?? $value);
        }

        foreach ($this->config->custom as $regex) {
            $value = Regex::replaceCallback(
                $regex,
                fn (array $m): string => $this->replacementFor($m[0]),
                $value,
            );
        }

        return $value;
    }

    /**
     * Every PAN candidate is Luhn-checked before replacement, so order
     * numbers and timestamps survive and real card numbers do not.
     */
    private function redactPans(string $value): string
    {
        return preg_replace_callback(
            Patterns::PAN,
            fn (array $m): string => Patterns::passesLuhn($m[0])
                ? $this->replacementFor($m[0])
                : $m[0],
            $value,
        ) ?? $value;
    }

    private function containsLikelySecret(string $value): bool
    {
        foreach ([Patterns::BEARER, Patterns::JWT, Patterns::AWS_KEY, Patterns::STRIPE_KEY] as $regex) {
            if (preg_match($regex, $value) === 1) {
                return true;
            }
        }

        if (preg_match_all(Patterns::PAN, $value, $matches) > 0) {
            foreach ($matches[0] as $candidate) {
                if (Patterns::passesLuhn($candidate)) {
                    return true;
                }
            }
        }

        return false;
    }

    /**
     * `[REDACTED]`, or `[REDACTED:ab12cd34]` when hash hints are on — the
     * first eight hex of an HMAC under a per-install salt, which answers "is
     * this the same token as yesterday?" without storing the token.
     */
    private function replacementFor(string $original): string
    {
        if (!$this->config->hashHint || $original === '') {
            return $this->config->replacement;
        }

        $salt = $this->config->hashSalt ?? '';
        $hint = substr(hash_hmac('sha256', $original, $salt), 0, 8);

        return sprintf('%s:%s', rtrim($this->config->replacement, ']'), $hint) . ']';
    }
}
