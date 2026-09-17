# wiretap

Capture outbound HTTP requests and responses in PHP — full URL, both sets of
headers, both bodies, timings and error codes — including calls made by code
you cannot edit.

```
composer require ssx/wiretap
```

This is the core package. It defines the record, the storage contracts, the
blocklist and the redaction pipeline. It does not capture anything on its own;
add one of the capture packages:

| Package | Captures | Requires |
| --- | --- | --- |
| [`ssx/wiretap-auto`](https://github.com/ssx/wiretap-auto) | curl and Guzzle, including vendor code, with no application changes | `ext-opentelemetry` |
| [`ssx/wiretap-guzzle`](https://github.com/ssx/wiretap-guzzle) | Guzzle clients you construct yourself | — |

## ⚠️ This is a debugging tool, not a logging product

Wiretap records complete outbound HTTP requests and responses, including
bodies. Those bodies routinely contain personal data, and on a commerce site
they can contain cardholder data.

**Do not leave it running.** Enable it to investigate a specific problem,
capture what you need, and turn it off. It is not intended to run permanently
and it is not designed to be a durable audit log.

Wiretap is **not PCI-DSS compliant** and it is **not GDPR compliant** on its
own, and it cannot be made so by configuration alone:

- PCI-DSS 3.2 forbids storing sensitive authentication data (CVV, full track,
  PIN) after authorisation — redacted or not. 3.4 requires PAN to be
  unreadable wherever it is stored. A table of raw gateway payloads brings
  your whole database, and every backup of it, into CDE scope.
- Captured payloads are personal data under GDPR. That means a lawful basis,
  Article 5(1)(e) storage limitation, Article 32 security of processing, and
  subject access and erasure requests that now reach into your log table. The
  log is itself an Article 33 liability.

Wiretap ships controls to reduce this exposure — a pre-capture blocklist that
drops matching URLs entirely, a redaction pipeline that is on by default, and
a retention command. **Configuring them correctly for your project is your
responsibility, not the package's.** We do not know which of your endpoints
carry cardholder data or which keys in your payloads hold personal data. You
do.

If you need permanent visibility into outbound traffic, you want metrics and
traces, not payload capture. Use OpenTelemetry directly.

## Requirements: why PHP 8.2+

Wiretap captures HTTP calls made by code you don't control — your vendor
directory, your payment SDK, a third-party client constructed with
`new GuzzleHttp\Client()` somewhere you'll never find. It does this by hooking
the functions themselves rather than asking you to route calls through a
wrapper.

That hooking is provided by `ext-opentelemetry`, which exposes PHP's
`zend_observer` API to userland. The extension itself runs on PHP 8.0+, but
observation of *internal* functions — `curl_exec`, `curl_setopt`,
`curl_multi_exec` — landed only in PHP 8.2. On 8.0 and 8.1 the hook API sees
userland functions and methods and nothing else.

The practical consequence: on PHP 8.1 we could auto-capture Guzzle (by hooking
`GuzzleHttp\Client::transfer`, a userland method) but raw `curl_exec()` in
vendor code would be completely invisible.

There is no way around that. uopz was last tagged in 2021, runkit7 is PECL
alpha and unmaintained since 2023, and the remaining option — rewriting PHP
source as it's read off disk, the way php-vcr does — requires disabling
opcache and is unusable in production.

So we require 8.2. One tier, no caveats, no "degraded mode" footnote someone
reads six hours into debugging a payment gateway.

PHP 8.1 reached end of life on 31 December 2025.

## The blocklist

Redaction reduces what is stored. The blocklist decides whether a call is
observed at all. Any request whose URL matches produces no record: no body is
read, no headers are copied, nothing enters the buffer.

```php
use Ssx\Wiretap\Blocklist\Blocklist;
use Ssx\Wiretap\Blocklist\ArrayBlocklistProvider;
use Ssx\Wiretap\Blocklist\PresetBlocklistProvider;

$blocklist = new Blocklist([
    new PresetBlocklistProvider(),          // payment gateways, on by default
    new ArrayBlocklistProvider([
        'api.internal.example.com',
        '*.myacquirer.net',
        'api.foo.com/v2/payments*',
        '~^https://api\.foo\.com/v2/(cards|tokens)~',
    ]),
]);
```

Four pattern forms are supported:

| Pattern | Matches | Does not match |
| --- | --- | --- |
| `api.stripe.com` | that host, any scheme or path | `api.stripe.com.evil.test` |
| `*.adyen.com` | the host and any subdomain | `notadyen.com` |
| `api.foo.com/v2/payments*` | host plus path prefix | `api.foo.com/v2/orders` |
| `~^https://api\.foo\.com/v2/~` | full-URL regex, `~`-delimited | — |

Matching is never substring-based against the raw URL. Providers are merged,
never intersected — registering another provider can only ever block more
traffic, never less.

If a provider throws, the blocklist **fails closed**: everything is treated as
blocked until it is fixed. A blocklist that silently empties itself when the
database is unreachable is worse than no blocklist at all.

## Licence

MIT.
