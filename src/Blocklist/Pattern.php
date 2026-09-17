<?php

declare(strict_types=1);

namespace Ssx\Wiretap\Blocklist;

use Ssx\Wiretap\Support\Regex;

/**
 * One compiled blocklist rule.
 *
 * Four forms are supported, in increasing order of specificity:
 *
 *   api.stripe.com                  exact host, any scheme or path
 *   *.adyen.com                     the host and any subdomain of it
 *   api.foo.com/v2/payments*        host plus a path prefix
 *   ~^https://api\.foo\.com/v2/~    a full-URL regex, tilde-delimited
 *
 * Matching is never substring-based against the raw URL. The obvious
 * implementation — str_contains($url, 'stripe.com') — matches
 * https://evil.test/?ref=stripe.com and fails to match nothing useful in
 * return, so it is not used anywhere in this class.
 */
final readonly class Pattern
{
    private const REGEX_DELIMITER = '~';

    private function __construct(
        public string $raw,
        private ?string $host,
        private bool $wildcardSubdomains,
        private ?string $pathPrefix,
        private ?string $regex,
    ) {
    }

    /**
     * @throws \InvalidArgumentException when the pattern cannot be compiled
     */
    public static function compile(string $pattern): self
    {
        $pattern = trim($pattern);

        if ($pattern === '') {
            throw new \InvalidArgumentException('Blocklist pattern cannot be empty.');
        }

        if (str_starts_with($pattern, self::REGEX_DELIMITER)) {
            return self::compileRegex($pattern);
        }

        return self::compileHostPattern($pattern);
    }

    private static function compileRegex(string $pattern): self
    {
        // A trailing delimiter is required; anything after it is treated as
        // flags. We add 'u' unconditionally so that IDN hosts behave.
        if (substr_count($pattern, self::REGEX_DELIMITER) < 2) {
            throw new \InvalidArgumentException(
                sprintf('Regex blocklist pattern "%s" is missing its closing delimiter.', $pattern)
            );
        }

        // Validate now rather than at match time, where a failure would be
        // silent and would mean traffic we intended to block gets captured.
        if (!Regex::isValid($pattern)) {
            throw new \InvalidArgumentException(
                sprintf('Blocklist pattern "%s" is not a valid regular expression.', $pattern)
            );
        }

        return new self(
            raw: $pattern,
            host: null,
            wildcardSubdomains: false,
            pathPrefix: null,
            regex: $pattern,
        );
    }

    private static function compileHostPattern(string $pattern): self
    {
        // Tolerate a scheme being present; it carries no matching information
        // because a blocked host is blocked over http and https alike.
        $withoutScheme = preg_replace('~^[a-z][a-z0-9+.-]*://~i', '', $pattern) ?? $pattern;

        $slash = strpos($withoutScheme, '/');
        $hostPart = $slash === false ? $withoutScheme : substr($withoutScheme, 0, $slash);
        $pathPart = $slash === false ? null : substr($withoutScheme, $slash);

        $wildcard = str_starts_with($hostPart, '*.');
        if ($wildcard) {
            $hostPart = substr($hostPart, 2);
        }

        $hostPart = self::normaliseHost($hostPart);

        if ($hostPart === '') {
            throw new \InvalidArgumentException(
                sprintf('Blocklist pattern "%s" does not contain a host.', $pattern)
            );
        }

        if ($pathPart !== null) {
            // A trailing * is the only wildcard supported in paths, and it is
            // implicit: every path pattern is a prefix match. Strip it so the
            // prefix comparison does not have to special-case it.
            $pathPart = rtrim($pathPart, '*');
        }

        return new self(
            raw: $pattern,
            host: $hostPart,
            wildcardSubdomains: $wildcard,
            pathPrefix: $pathPart === '' ? null : $pathPart,
            regex: null,
        );
    }

    public function matches(string $url): bool
    {
        if ($this->regex !== null) {
            $result = preg_match($this->regex, $url);

            // preg_match returns false on a runtime failure — invalid UTF-8 in
            // the subject, or a backtrack limit. Treating that as "not
            // blocked" would let exactly the traffic a rule exists to stop
            // through, so an execution failure blocks.
            return $result === false || $result === 1;
        }

        $parts = parse_url($url);

        // curl accepts a scheme-less URL and defaults to http, so
        // `api.stripe.com/v1/charges` is a real request that parse_url reads
        // as a path with no host — and the gate returned false for it.
        if (is_array($parts) && !isset($parts['host']) && !str_contains($url, '://')) {
            $parts = parse_url('http://' . ltrim($url, '/'));
        }

        if ($parts === false || !isset($parts['host'])) {
            // Unreadable. A rule exists to stop this traffic, so an address we
            // cannot understand is blocked rather than waved through.
            return true;
        }

        if (!$this->hostMatches(self::normaliseHost($parts['host']))) {
            return false;
        }

        if ($this->pathPrefix === null) {
            return true;
        }

        return str_starts_with(
            self::normalisePath($parts['path'] ?? '/'),
            self::normalisePath($this->pathPrefix),
        );
    }

    /**
     * Normalise a path the way the request reaching the wire will look.
     *
     * curl resolves dot-segments before sending, so `/v2/../v2/payments` is
     * `/v2/payments` on the wire while a literal prefix comparison saw two
     * different strings. Percent-encoding and repeated slashes hide the same
     * path equally well, and case is folded because a gate that blocks too
     * much is the safe direction.
     */
    private static function normalisePath(string $path): string
    {
        $path = rawurldecode($path);
        $path = preg_replace('~/+~', '/', $path) ?? $path;

        $segments = [];

        foreach (explode('/', $path) as $segment) {
            if ($segment === '.' || $segment === '') {
                continue;
            }

            if ($segment === '..') {
                array_pop($segments);

                continue;
            }

            $segments[] = $segment;
        }

        $normalised = '/' . implode('/', $segments);

        // A trailing slash is not a different resource for prefix purposes.
        return strtolower(rtrim($normalised, '/')) ?: '/';
    }

    private function hostMatches(string $host): bool
    {
        if ($host === $this->host) {
            return true;
        }

        // The leading dot is what stops *.adyen.com matching notadyen.com.
        return $this->wildcardSubdomains
            && str_ends_with($host, '.' . $this->host);
    }

    /**
     * Lowercase, strip a trailing dot, drop a port, and convert IDN to
     * punycode where the intl extension is available so that a pattern
     * written in Unicode matches a URL written in ASCII and vice versa.
     */
    private static function normaliseHost(string $host): string
    {
        $host = strtolower(trim($host));
        $host = rtrim($host, '.');

        // Strip a port, being careful not to mangle a bracketed IPv6 literal.
        if (!str_starts_with($host, '[') && ($colon = strrpos($host, ':')) !== false) {
            $host = substr($host, 0, $colon);
        }

        if ($host !== '' && !preg_match('/^[\x20-\x7f]*$/', $host) && function_exists('idn_to_ascii')) {
            $ascii = idn_to_ascii($host, IDNA_DEFAULT, INTL_IDNA_VARIANT_UTS46);

            if (is_string($ascii) && $ascii !== '') {
                $host = $ascii;
            }
        }

        return $host;
    }
}
