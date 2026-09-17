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
| [`ssx/wiretap-auto`](https://github.com/ssx/wiretap-auto) | **synchronous** curl and Guzzle, including vendor code, with no application changes | `ext-opentelemetry` |
| [`ssx/wiretap-guzzle`](https://github.com/ssx/wiretap-guzzle) | Guzzle clients you construct — sync, async and pools | — |
| [`ssx/wiretap-symfony`](https://github.com/ssx/wiretap-symfony) | Symfony HttpClient | — |

`ssx/wiretap-auto` hooks `curl_exec` and **not** `curl_multi_*`, so async
Guzzle (`getAsync()`, `Pool`) and Symfony's `CurlHttpClient` are not captured
by it. Guzzle's default handler only reaches `curl_exec` on its synchronous
branch. If you own the client, the bridge packages cover async properly; the
gap is vendor code you cannot edit making async calls. See that package's
README.

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

## Getting the data back out

```
vendor/bin/wiretap list --host=api.example.com --limit=20

  #   WHEN           METHOD STATUS     TIME  URI
  1   12s ago        POST   502      1,841ms  https://api.example.com/v2/orders
  2   14s ago        GET    200        212ms  https://api.example.com/v2/orders/9f1

vendor/bin/wiretap show 1
```

`show` prints the full pair: headers both ways, pretty-printed bodies, and a
timing breakdown. A bare number means "the nth row of the listing I just looked
at", which is how people actually refer to these.

| Command | What it does |
| --- | --- |
| `list` | recorded exchanges, newest first |
| `show <n\|id>` | one exchange in full; `--curl`, `--har`, `--json`, `--raw` |
| `trace <correlation-id>` | every call made during one inbound request, as a waterfall |
| `export` | HAR 1.2 to stdout or `--out=file.har` |
| `prune --older-than=7d` | delete logs past a retention window |
| `doctor` | what is and is not being captured, and why |

Filters apply to `list`, `show` and `export`: `--host`, `--method`,
`--status=502`, `--status=5xx`, `--failed`, `--since=30m`, `--limit`,
`--offset`.

### HAR export

```bash
vendor/bin/wiretap export --failed --out=failures.har
```

The single highest-leverage thing in the package, and barely any code. HAR 1.2
is what Chrome DevTools, Firefox, Proxyman, Charles, Insomnia and Postman all
import, so supporting it makes every one of them a viewer for wiretap's data.
Building a bespoke UI instead would buy a worse version of what five mature
tools already do.

Wiretap's own context — correlation id, transport, route, console command,
truncation and omission reasons — rides along in a `_wiretap` key, which HAR
viewers display in their detail panes.

### `wiretap doctor`

Answers "why is nothing being recorded", which otherwise costs an afternoon:
PHP version, extension state, log directory, whether `WIRETAP_ENABLED` is set,
recent traffic by host, and blocklist pattern counts per source.

It also warns when capture has been left on for more than 24 hours. A tool
documented as temporary but behaving identically on day ninety will be left on;
the warning is the only part of that policy that actually runs.


## Testing

Wiretap doubles as an assertion library for outbound HTTP. This is worth
having even if you never switch capture on in production.

```php
use Ssx\Wiretap\Wiretap;
use Ssx\Wiretap\Exchange;

Wiretap::fake();

$service->syncOrders();

Wiretap::assertSent('api.example.com', times: 2);
Wiretap::assertSent(fn (Exchange $e) => $e->method === 'POST' && $e->status === 201);
Wiretap::assertNothingSentTo('api.stripe.com');
Wiretap::assertSentCount(2);
```

`fake()` captures in memory, keeps everything, and turns redaction **off** —
asserting on a value the redactor would have replaced is the point of a test
double. It also starts with an empty blocklist, so a test asserting on a
payment call is not defeated by the payment-gateways preset.

Failures list what actually happened, so the first move is not to add a
`dump()` and run again:

```
Expected a request to host [nope.example.com], but none was sent.

Recorded:
  1. POST https://api.example.com/v1/orders -> 201
  2. GET https://api.example.com/v1/health -> 500
```

Assertions route through PHPUnit's `Assert` when it is loaded, so a failure
counts as a failed assertion rather than an errored test. Without PHPUnit they
throw `Ssx\Wiretap\Testing\AssertionFailed`, so the API works under Pest,
PHPUnit or anything else.

### Inspecting a capture

```php
$calls = Wiretap::recorded();

$calls->toHost('api.example.com');
$calls->withMethod('POST');
$calls->withStatus(500);
$calls->failed();
$calls->first()->requestBody->bytes;

file_put_contents('test-run.har', $calls->toHar());
```

That last line is occasionally the fastest way to understand a failing
integration test: open it in the tool you would have used against production.

### Scoped capture in a running application

```php
$result = Wiretap::debug(fn () => $service->syncOrders(), $calls);

echo count($calls), ' calls made';
```

Captures only what happened inside the closure, regardless of whether capture
is globally enabled or sampled, and restores the previous recorder afterwards
— including when the closure throws.


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
