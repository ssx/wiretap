<?php

declare(strict_types=1);

namespace Ssx\Wiretap\Redaction;

use Ssx\Wiretap\CapturedBody;
use Ssx\Wiretap\Exchange;
use Ssx\Wiretap\Headers;
use Ssx\Wiretap\TransferError;
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

        // Values removed from the URL and the headers are known secrets. An
        // API that echoes its input back — and a great many do — would
        // otherwise hand the same value straight back in the response body,
        // where no structural rule is looking for it.
        $known = new KnownSecrets($this->config->minEchoedSecretLength);

        $redacted = $exchange
            ->withUri($this->redactUrl($exchange->uri, $known))
            ->withRequestHeaders($this->redactHeaders($exchange->requestHeaders, $known))
            ->withResponseHeaders($this->redactHeaders($exchange->responseHeaders, $known))
            ->withRequestBody($this->redactBody($exchange->requestBody, $known))
            ->withResponseBody($this->redactBody($exchange->responseBody, $known));

        // Free text that is persisted like anything else. A Guzzle
        // RequestException message embeds the full request URI, so an
        // exception carried a credential straight past the URL redaction that
        // had just removed it.
        return $redacted
            ->withError($this->redactError($redacted->error, $known))
            ->withContext($this->redactContext($redacted->context, $known))
            // Free text like everything above. A reason phrase is server-
            // controlled, and tags are supplied by integrations.
            ->withReason($redacted->reason === null ? null : $this->redactText($redacted->reason, $known))
            ->withTags(array_map(fn (string $t): string => $this->redactText($t, $known), $redacted->tags));
    }

    /**
     * Layer 2. Rewrites the query string properly rather than regexing the
     * whole URL, so a parameter value that happens to contain an ampersand
     * cannot smuggle plaintext through.
     */
    public function redactUrl(string $url, ?KnownSecrets $known = null): string
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
            $query = http_build_query($this->redactQueryParams($params, $known), '', '&', PHP_QUERY_RFC3986);
        }

        if ($known !== null && isset($parts['pass'])) {
            $known->remember((string) $parts['pass']);
        }

        return $this->rebuildUrl($parts, $query);
    }

    /**
     * @param array<array-key, mixed> $params
     *
     * @return array<array-key, mixed>
     */
    private function redactQueryParams(array $params, ?KnownSecrets $known = null): array
    {
        foreach ($params as $name => $value) {
            // Sensitivity is decided before recursing. Checking the leaf only
            // meant `?token[]=secret` recursed into an array whose keys are
            // 0, 1, 2 — none of which is a sensitive name — and the value
            // survived untouched.
            if ($this->isSensitiveQueryParam((string) $name)) {
                $params[$name] = is_array($value)
                    ? $this->redactEverything($value, $known)
                    : $this->redactLeaf($value, $known);

                continue;
            }

            if (is_array($value)) {
                /** @var array<array-key, mixed> $value */
                $params[$name] = $this->redactQueryParams($value, $known);
            }
        }

        return $params;
    }

    /**
     * Every leaf beneath a sensitive parameter is itself sensitive.
     *
     * @param array<array-key, mixed> $values
     *
     * @return array<array-key, mixed>
     */
    private function redactEverything(array $values, ?KnownSecrets $known = null): array
    {
        foreach ($values as $key => $value) {
            $values[$key] = is_array($value)
                ? $this->redactEverything($value, $known)
                : $this->redactLeaf($value, $known);
        }

        return $values;
    }

    private function redactLeaf(mixed $value, ?KnownSecrets $known = null): string
    {
        $original = is_scalar($value) ? (string) $value : '';
        $known?->remember($original);

        return $this->replacementFor($original);
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
    public function redactHeaders(Headers $headers, ?KnownSecrets $known = null): Headers
    {
        return $headers->map(function (string $name, string $value) use ($known): string {
            if ($this->isSensitiveHeader($name)) {
                $known?->remember($value);
                $known?->rememberCredentialValue($value);
                $known?->rememberCookieValues($value);

                return $this->replacementFor($value);
            }

            // A header that carries a URL carries everything in its query
            // string. `Location: https://host/?token=...` survived untouched
            // while the same token was being stripped from the exchange URI.
            if ($this->isUrlHeader($name)) {
                $value = $this->redactUrl($value, $known);
            }

            $value = $this->applyPatterns($value);

            // Truncation is last. Cutting first destroyed the evidence the
            // detectors need: a header ending in a card number kept its
            // leading digits and lost the rest, leaving a fragment nothing
            // would ever match again.
            if (strlen($value) > $this->config->maxHeaderValueBytes) {
                $value = substr($value, 0, $this->config->maxHeaderValueBytes) . '…[truncated]';
            }

            return $value;
        });
    }

    private function isUrlHeader(string $name): bool
    {
        return in_array(strtolower($name), [
            'location',
            'content-location',
            'referer',
            'refresh',
        ], true);
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
     * Exception messages routinely embed the request URI, and therefore its
     * query string. Redacting the URI while persisting the message verbatim
     * put the credential straight back in the record.
     */
    private function redactError(?TransferError $error, KnownSecrets $known): ?TransferError
    {
        if ($error === null) {
            return null;
        }

        return new TransferError($error->errno, $this->redactText($error->message, $known), $error->class);
    }

    /**
     * Context is supplied by framework integrations and can contain a route
     * path with a secret in it — a password-reset token, for instance.
     *
     * @param array<string, scalar|null> $context
     *
     * @return array<string, scalar|null>
     */
    private function redactContext(array $context, KnownSecrets $known): array
    {
        foreach ($context as $key => $value) {
            if (!is_string($value) || $value === '') {
                continue;
            }

            $context[$key] = $this->redactText($value, $known);
        }

        return $context;
    }

    /**
     * Custom patterns that will never match because they do not compile.
     *
     * Surfaced so `wiretap doctor` can say so out loud rather than leaving
     * someone to believe a rule is running.
     *
     * @return list<string>
     */
    public function invalidPatterns(): array
    {
        $invalid = [];

        foreach ($this->config->custom as $regex) {
            if (!Regex::isValid($regex)) {
                $invalid[] = $regex;
            }
        }

        return $invalid;
    }

    /**
     * Run the free-text layers over a persisted string field.
     */
    private function redactText(string $text, KnownSecrets $known): string
    {
        $clean = $this->redactUrlsIn($text, $known);
        $clean = $this->applyPatterns($clean);

        return $known->scrub($clean, $this->config->replacement);
    }

    /**
     * Rewrite any absolute URL embedded in free text.
     */
    private function redactUrlsIn(string $text, ?KnownSecrets $known = null): string
    {
        return Regex::replaceCallback(
            '~https?://[^\s\'"<>]+~i',
            fn (array $m): string => $this->redactUrl($m[0], $known),
            $text,
        );
    }

    /**
     * Layers 1, 4, 5 and 6.
     */
    public function redactBody(CapturedBody $body, ?KnownSecrets $known = null): CapturedBody
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

        // Layer 4, then 5, then the echoed-value sweep.
        $structured = $this->redactStructured($bytes, $body->contentType, $inspected);

        // The most important rule here. If structural rules are configured and
        // the body could not be parsed to apply them, the body is dropped
        // rather than stored.
        //
        // The failing case is not exotic: a capture layer truncates a large
        // JSON payload, the prefix no longer parses, structural redaction
        // silently does nothing, and a password sitting in the first hundred
        // bytes is written out in full. The regex detectors do not save you —
        // an ordinary password matches none of them.
        // A broken custom pattern means a configured rule did not run. Treat
        // that exactly like a body whose structural rules could not be
        // applied: drop it rather than store something an intended rule never
        // examined.
        if ($this->invalidPatterns() !== [] && $this->config->omitUninspectableBodies) {
            return CapturedBody::omitted(
                CapturedBody::OMITTED_REDACTED,
                $body->size,
                $body->contentType,
                $body->sha256,
            );
        }

        if (!$inspected && $this->config->bodyPaths !== [] && $this->config->omitUninspectableBodies) {
            return CapturedBody::omitted(
                CapturedBody::OMITTED_REDACTED,
                $body->size,
                $body->contentType,
                $body->sha256,
            );
        }

        $bytes = $this->applyPatterns($structured);

        if ($known !== null) {
            $bytes = $known->scrub($bytes, $this->config->replacement);
        }

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
    private function redactStructured(string $bytes, ?string $contentType, ?bool &$inspected = null): string
    {
        if ($this->config->bodyPaths === []) {
            $inspected = true;

            return $bytes;
        }

        $inspected = false;
        $type = strtolower(explode(';', $contentType ?? '')[0]);

        if (str_contains($type, 'x-www-form-urlencoded')) {
            parse_str($bytes, $form);
            $form = $this->redactPaths($form, $this->config->bodyPaths);
            $inspected = true;

            return http_build_query($form, '', '&', PHP_QUERY_RFC3986);
        }

        $decoded = json_decode($bytes, true);

        if (!is_array($decoded)) {
            // Not JSON, malformed, or a truncated prefix. The caller decides
            // what to do; it must not be treated as successfully inspected.
            return $bytes;
        }

        $redacted = $this->redactPaths($decoded, $this->config->bodyPaths);
        $encoded = json_encode($redacted, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);

        if ($encoded === false) {
            return $bytes;
        }

        $inspected = true;

        return $encoded;
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
            if (!Regex::isValid($regex)) {
                // Counted, not silently skipped. A rule someone believes is
                // protecting them and quietly is not is the worst outcome
                // available here, so bodies are treated as uninspectable while
                // any custom pattern is broken.
                continue;
            }

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
            function (array $m): string {
                $found = Patterns::findPans($m[0]);

                if ($found === []) {
                    return $m[0];
                }

                // Replace only the card inside the match, so an adjacent
                // numeric field alongside it survives.
                return str_replace($found[0], $this->replacementFor($found[0]), $m[0]);
            },
            $value,
        ) ?? $value;
    }

    private function containsLikelySecret(string $value): bool
    {
        // Scan the decoded form too. JSON escaping hides a card number as
        // \u0031 digits and a token as abc\/def, neither of which the
        // detectors match against the raw serialised text.
        $decoded = json_decode($value, true);

        if (is_array($decoded)) {
            $flat = $this->flattenToText($decoded);

            if ($flat !== '' && $this->scanForSecrets($flat)) {
                return true;
            }
        }

        return $this->scanForSecrets($value);
    }

    /**
     * @param array<array-key, mixed> $data
     */
    private function flattenToText(array $data): string
    {
        $parts = [];

        array_walk_recursive($data, static function (mixed $value) use (&$parts): void {
            if (is_scalar($value)) {
                $parts[] = (string) $value;
            }
        });

        return implode("\n", $parts);
    }

    private function scanForSecrets(string $value): bool
    {
        foreach ([Patterns::BEARER, Patterns::JWT, Patterns::AWS_KEY, Patterns::STRIPE_KEY] as $regex) {
            if (preg_match($regex, $value) === 1) {
                return true;
            }
        }

        if (preg_match_all(Patterns::PAN, $value, $matches) > 0) {
            foreach ($matches[0] as $candidate) {
                if (Patterns::findPans($candidate) !== []) {
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
