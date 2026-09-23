<?php

declare(strict_types=1);

use Ssx\Wiretap\Blocklist\ArrayBlocklistProvider;
use Ssx\Wiretap\Blocklist\Blocklist;
use Ssx\Wiretap\Blocklist\Pattern;
use Ssx\Wiretap\Blocklist\PresetBlocklistProvider;
use Ssx\Wiretap\Contract\BlocklistProvider;
use Ssx\Wiretap\Recorder;

describe('ip literals spelled the way curl still accepts', function (): void {
    // Every one of these reaches 169.254.169.254 through curl, which parses
    // IPv4 the way inet_aton does. A string comparison against the dotted
    // quad let the metadata preset be walked around, and the instance's IAM
    // credentials were recorded in plaintext.
    it('blocks every spelling of the metadata address', function (string $url): void {
        expect((new Blocklist([PresetBlocklistProvider::all()]))->blocks($url))->toBeTrue();
    })->with([
        'decimal' => 'http://2852039166/latest/meta-data/',
        'hex' => 'http://0xa9fea9fe/latest/meta-data/',
        'upper hex' => 'http://0XA9FEA9FE/latest/meta-data/',
        'octal quads' => 'http://0251.0376.0251.0376/latest/meta-data/',
        'two-part short form' => 'http://169.16689662/latest/meta-data/',
        'three-part short form' => 'http://169.254.43518/latest/meta-data/',
        'mixed bases' => 'http://0xa9.254.0251.254/latest/meta-data/',
        'trailing dot' => 'http://169.254.169.254./latest/meta-data/',
        'v4-mapped v6' => 'http://[::ffff:169.254.169.254]/latest/meta-data/',
        'v4-mapped v6 in hex' => 'http://[::ffff:a9fe:a9fe]/latest/meta-data/',
        'expanded v6' => 'http://[fd00:ec2:0::254]/latest/meta-data/',
        'fully expanded v6' => 'http://[fd00:0ec2:0:0:0:0:0:254]/latest/meta-data/',
        'v6 with zone id' => 'http://[fd00:ec2::254%25eth0]/latest/meta-data/',
        'alibaba decimal' => 'http://1684301000/latest/meta-data/',
    ]);

    it('still lets ordinary addresses and hostnames through', function (string $url): void {
        expect((new Blocklist([PresetBlocklistProvider::all()]))->blocks($url))->toBeFalse();
    })->with([
        'http://169.254.169.253/',
        'http://2852039167/',
        'http://[fd00:ec2::253]/',
        'http://[::ffff:10.0.0.1]/',
        'https://1e100.net/',
        'https://api.example.com/',
        'https://123.example.com/',
    ]);

    it('matches a rule written in any spelling against a url in any other', function (): void {
        // The rule side is canonicalised too, so an operator who writes the
        // address in hex is not quietly protected against the decimal form
        // only.
        $pattern = Pattern::compile('0x7f000001');

        expect($pattern->matches('http://127.0.0.1/'))->toBeTrue()
            ->and($pattern->matches('http://2130706433/'))->toBeTrue()
            ->and($pattern->matches('http://127.1/'))->toBeTrue()
            ->and($pattern->matches('http://[::ffff:127.0.0.1]/'))->toBeTrue()
            ->and($pattern->matches('http://127.0.0.2/'))->toBeFalse();
    });

    it('treats an unbracketed v6 rule as an address, not a host and port', function (): void {
        // `fd00:ec2::254` used to lose everything after its last colon, as if
        // that were a port, and compiled to the host `fd00:ec2:`.
        $pattern = Pattern::compile('fd00:ec2::254');

        expect($pattern->matches('http://[fd00:ec2:0:0:0:0:0:254]/'))->toBeTrue()
            ->and($pattern->matches('http://[fd00:ec2::1]/'))->toBeFalse();
    });

    it('reads a name that starts with a digit as a name', function (): void {
        // `3ds` is a hostname. Taking it for a malformed number made the rule
        // fail to compile, and a host the operator had blocked was captured.
        $blocklist = new Blocklist([new ArrayBlocklistProvider(['3ds', '1e100.net'])]);

        expect($blocklist->blocks('http://3ds/payments'))->toBeTrue()
            ->and($blocklist->blocks('https://1e100.net/'))->toBeTrue()
            ->and($blocklist->blocks('https://3ds.example.com/'))->toBeFalse()
            ->and($blocklist->errors())->toBe([]);
    });

    it('fails closed on an address that is numeric but not valid', function (string $url): void {
        // curl rejects or reinterprets these; either way the gate cannot say
        // with confidence which host they reach, so a rule that exists to stop
        // traffic stops them.
        expect(Pattern::compile('169.254.169.254')->matches($url))->toBeTrue();
    })->with([
        'octal with an eight' => 'http://0258.254.169.254/',
        'part overflow' => 'http://169.254.169.256/',
        'too many parts' => 'http://1.2.3.4.5/',
        'bare 0x' => 'http://0x.1.2.3/',
        'over 32 bits' => 'http://4294967296/',
        'bad v6' => 'http://[fd00::ec2::254]/',
    ]);
});

describe('hosts that become numeric through IDNA', function (): void {
    it('blocks a host whose unicode digits or dots map to an address', function (string $url): void {
        // idn_to_ascii maps a fullwidth 2 to 2 and 。 to a dot, and curl
        // built with IDN support connects to the result. The check for a
        // numeric host ran before that mapping, so it saw a name.
        expect((new Blocklist([PresetBlocklistProvider::all()]))->blocks($url))->toBeTrue();
    })->with([
        'fullwidth digit, encoded' => 'http://%EF%BC%92852039166/latest/meta-data/',
        'fullwidth digit' => "http://\u{FF12}852039166/latest/meta-data/",
        'ideographic full stops, encoded' => 'http://0251%E3%80%820376%E3%80%820251%E3%80%820376/latest/meta-data/',
        'ideographic full stops' => "http://169\u{3002}254\u{3002}169\u{3002}254/latest/meta-data/",
    ]);

    it('rejects a rule that is only numeric once mapped', function (): void {
        $blocklist = new Blocklist([new ArrayBlocklistProvider(["\u{FF12}\u{FF18}\u{FF15}\u{FF12}\u{FF10}\u{FF13}\u{FF19}\u{FF11}\u{FF16}\u{FF16}"])]);

        expect($blocklist->errors())->toHaveCount(1);
    });

    it('still matches an ordinary unicode name', function (): void {
        $pattern = Pattern::compile('bücher.example');

        expect($pattern->matches('https://xn--bcher-kva.example/'))->toBeTrue()
            ->and($pattern->matches('https://example.com/'))->toBeFalse();
    });
});

describe('percent-encoded hosts', function (): void {
    it('decodes the host before matching, the way curl does', function (string $url): void {
        expect((new Blocklist([new PresetBlocklistProvider()]))->blocks($url))->toBeTrue();
    })->with([
        'https://api.%73tripe.com/v1/charges',
        'https://%61%70%69.stripe.com/v1/charges',
        'https://API.%53TRIPE.COM/v1/charges',
    ]);

    it('fails closed on a host that is still encoded after one decode', function (): void {
        // %2573 decodes to %73. Whether anything decodes it again is not
        // something the gate can know, so it does not guess.
        expect(Pattern::compile('api.stripe.com')->matches('https://api.%2573tripe.com/'))->toBeTrue();
    });

    it('applies the same decoding to regex rules', function (): void {
        $pattern = Pattern::compile('~^https?://api\.stripe\.com/~');

        expect($pattern->matches('https://api.%73tripe.com/v1'))->toBeTrue()
            ->and($pattern->matches('https://api.example.com/v1'))->toBeFalse();
    });

    it('decodes a scheme-less url for regex rules too', function (): void {
        expect(Pattern::compile('~api\.stripe\.com~')->matches('api.%73tripe.com/v1/charges'))->toBeTrue();
    });

    it('blocks an ambiguous host under a regex rule as a host rule does', function (): void {
        expect(Pattern::compile('~^https://api\.stripe\.com/~')->matches('https://api.%2573tripe.com/'))->toBeTrue();
    });
});

describe('a provider that fetches its rules over instrumented http', function (): void {
    it('does not recurse into compilation from inside itself', function (): void {
        // The provider's own HTTP call reaches the capture hooks, which ask
        // the gate, which compiles, which calls the provider again — until
        // memory runs out. The nested check must see a gate that is busy and
        // decline to capture, not start over.
        $recorder = null;
        $calls = 0;

        $provider = new class ($recorder, $calls) implements BlocklistProvider {
            public function __construct(public ?Recorder &$recorder, public int &$calls)
            {
            }

            public function patterns(): iterable
            {
                ++$this->calls;

                if ($this->calls > 5) {
                    throw new \RuntimeException('recursed');
                }

                // What an HTTP-backed provider does, through the hooks.
                $nested = $this->recorder?->shouldCapture('https://rules.example.com/blocklist.txt');

                return $nested === true ? ['nested-said-yes.example.com'] : ['api.example.com'];
            }

            public function name(): string
            {
                return 'http';
            }
        };

        $recorder = new Recorder(blocklist: new Blocklist([$provider]));

        expect($recorder->shouldCapture('https://api.example.com/x'))->toBeFalse()
            ->and($calls)->toBe(1)
            ->and($recorder->blocklist()->hasFailedClosed())->toBeFalse()
            ->and($recorder->shouldCapture('https://other.example.com/x'))->toBeTrue();
    });

    it('blocks a nested check made straight against the blocklist', function (): void {
        $blocklist = null;
        $nested = null;

        $provider = new class ($blocklist, $nested) implements BlocklistProvider {
            public function __construct(public ?Blocklist &$blocklist, public ?bool &$nested)
            {
            }

            public function patterns(): iterable
            {
                $this->nested ??= $this->blocklist?->blocks('https://rules.example.com/');

                return ['api.example.com'];
            }

            public function name(): string
            {
                return 'http';
            }
        };

        $blocklist = new Blocklist([$provider]);

        expect($blocklist->blocks('https://other.example.com/'))->toBeFalse()
            ->and($nested)->toBeTrue();
    });
});

describe('ordinary rules are unaffected', function (): void {
    it('still compiles and matches plain host and path rules', function (): void {
        $blocklist = new Blocklist([new ArrayBlocklistProvider(['api.example.com:8443', '*.adyen.com', 'api.foo.com/v2/payments*'])]);

        expect($blocklist->blocks('https://api.example.com/x'))->toBeTrue()
            ->and($blocklist->blocks('https://pal.adyen.com/x'))->toBeTrue()
            ->and($blocklist->blocks('https://api.foo.com/v2/payments/1'))->toBeTrue()
            ->and($blocklist->blocks('https://api.foo.com/v2/refunds'))->toBeFalse()
            ->and($blocklist->errors())->toBe([]);
    });
});
