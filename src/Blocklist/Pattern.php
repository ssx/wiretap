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

        $hostPart = self::normaliseHost(self::stripPort($hostPart));

        if ($hostPart === null) {
            throw new \InvalidArgumentException(
                sprintf('Blocklist pattern "%s" does not contain a host that can be read unambiguously.', $pattern)
            );
        }

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
            // Tried against the URL as written and as curl will read it, so a
            // rule for api.stripe.com also stops api.%73tripe.com.
            foreach (array_unique([$url, self::canonicalUrl($url) ?? $url]) as $candidate) {
                $result = preg_match($this->regex, $candidate);

                // preg_match returns false on a runtime failure — invalid
                // UTF-8 in the subject, or a backtrack limit. Treating that as
                // "not blocked" would let exactly the traffic a rule exists to
                // stop through, so an execution failure blocks.
                if ($result === false || $result === 1) {
                    return true;
                }
            }

            return false;
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

        $host = self::normaliseHost($parts['host']);

        // A host that cannot be read one way only — still percent-encoded
        // after decoding, or numeric but not a valid address — may reach the
        // host this rule names. Blocking it is the safe reading.
        if ($host === null) {
            return true;
        }

        if (!$this->hostMatches($host)) {
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
     * The URL with its host replaced by the canonical form, for regex rules.
     */
    private static function canonicalUrl(string $url): ?string
    {
        $parts = parse_url($url);

        if (!is_array($parts) || !isset($parts['host'])) {
            return null;
        }

        $host = self::normaliseHost($parts['host']);

        if ($host === null) {
            return null;
        }

        $scheme = isset($parts['scheme']) ? $parts['scheme'] . '://' : '//';
        $port = isset($parts['port']) ? ':' . $parts['port'] : '';
        $path = $parts['path'] ?? '';
        $query = isset($parts['query']) ? '?' . $parts['query'] : '';

        return $scheme . $host . $port . $path . $query;
    }

    /**
     * Drop a `:port` from a rule's host, leaving an IPv6 literal intact.
     */
    private static function stripPort(string $host): string
    {
        $host = trim($host);

        if (str_starts_with($host, '[')) {
            $close = strpos($host, ']');

            return $close === false ? $host : substr($host, 0, $close + 1);
        }

        // Two or more colons is an unbracketed IPv6 literal, not host:port.
        if (substr_count($host, ':') === 1) {
            return substr($host, 0, (int) strpos($host, ':'));
        }

        return $host;
    }

    /**
     * The host as curl will connect to it, or null when that is ambiguous.
     *
     * A string comparison against the rule was not enough, because curl
     * reads a host in more ways than one. It percent-decodes it, so
     * `api.%73tripe.com` is api.stripe.com. It parses IPv4 the way inet_aton
     * does, so `2852039166`, `0xa9fea9fe`, `0251.0376.0251.0376` and
     * `169.254.43518` are all 169.254.169.254. And IPv6 has many spellings of
     * one address, including the IPv4-mapped `::ffff:a9fe:a9fe`. Every one of
     * those walked past the metadata preset.
     *
     * So both sides are reduced to one form: a dotted quad for IPv4 (including
     * v4-mapped v6), the compressed inet_ntop form in brackets for IPv6, and a
     * lowercase, dot-trimmed, punycoded name otherwise. Where the host cannot
     * be read one way only, null is returned and the caller fails closed.
     */
    private static function normaliseHost(string $host): ?string
    {
        $host = trim($host);

        if (str_contains($host, '%')) {
            $host = rawurldecode($host);

            // Still encoded after one decode, or decoded into bytes no host
            // contains. Whether anything decodes it again is not knowable.
            if (str_contains($host, '%') && !self::isBracketedWithZone($host)) {
                return null;
            }
        }

        if (preg_match('/[\x00-\x20\x7f\/\\\\?#@]/', $host) === 1) {
            return null;
        }

        $host = strtolower($host);

        if (str_starts_with($host, '[') || substr_count($host, ':') >= 2) {
            return self::normaliseIpv6(trim($host, '[]'));
        }

        $host = rtrim($host, '.');

        if ($host === '') {
            return '';
        }

        if (self::looksNumeric($host)) {
            return self::normaliseIpv4($host);
        }

        if (!preg_match('/^[\x20-\x7f]*$/', $host) && function_exists('idn_to_ascii')) {
            $ascii = idn_to_ascii($host, IDNA_DEFAULT, INTL_IDNA_VARIANT_UTS46);

            if (is_string($ascii) && $ascii !== '') {
                $host = $ascii;
            }
        }

        return $host;
    }

    private static function isBracketedWithZone(string $host): bool
    {
        return str_starts_with($host, '[') && preg_match('/^\[[0-9a-f:.]+%[^%\]]+\]$/i', $host) === 1;
    }

    /**
     * Whether every dot-separated part is a number in some base, which is
     * what makes curl read the host as an IPv4 address rather than a name.
     */
    private static function looksNumeric(string $host): bool
    {
        foreach (explode('.', $host) as $part) {
            if (preg_match('/^(0x[0-9a-z]*|[0-9][0-9a-z]*)$/', $part) !== 1) {
                return false;
            }
        }

        return true;
    }

    /**
     * inet_aton: one to four parts, each decimal, 0x-hex or 0-octal, the
     * last filling whatever bytes remain.
     */
    private static function normaliseIpv4(string $host): ?string
    {
        $parts = explode('.', $host);

        if (count($parts) > 4) {
            return null;
        }

        $values = [];

        foreach ($parts as $part) {
            if (preg_match('/^0x([0-9a-f]+)$/', $part, $m) === 1) {
                $digits = ltrim($m[1], '0');
                $value = strlen($digits) > 8 ? null : (int) hexdec($digits === '' ? '0' : $digits);
            } elseif (preg_match('/^0[0-7]*$/', $part) === 1) {
                $digits = ltrim($part, '0');
                $value = strlen($digits) > 11 ? null : (int) octdec($digits === '' ? '0' : $digits);
            } elseif (preg_match('/^[1-9][0-9]*$/', $part) === 1) {
                $value = strlen($part) > 10 ? null : (int) $part;
            } else {
                // 0x with no digits, an 8 or 9 in an octal part, stray letters.
                return null;
            }

            if ($value === null) {
                return null;
            }

            $values[] = $value;
        }

        $last = array_pop($values);

        foreach ($values as $value) {
            if ($value > 0xff) {
                return null;
            }
        }

        if ($last > (0xffffffff >> (8 * count($values)))) {
            return null;
        }

        $address = $last;

        foreach ($values as $index => $value) {
            $address |= $value << (8 * (3 - $index));
        }

        $dotted = long2ip($address);

        return is_string($dotted) ? $dotted : null;
    }

    private static function normaliseIpv6(string $host): ?string
    {
        // A zone id names an interface, not a different address.
        $zone = strpos($host, '%');

        if ($zone !== false) {
            $host = substr($host, 0, $zone);
        }

        $binary = @inet_pton($host);

        if ($binary === false || strlen($binary) !== 16) {
            return null;
        }

        // ::ffff:a.b.c.d is the IPv4 address, reached over a v6 socket.
        if (str_starts_with($binary, str_repeat("\0", 10) . "\xff\xff")) {
            $v4 = inet_ntop(substr($binary, 12));

            return is_string($v4) ? $v4 : null;
        }

        $text = inet_ntop($binary);

        return is_string($text) ? '[' . $text . ']' : null;
    }
}
