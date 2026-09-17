<?php

declare(strict_types=1);

namespace Ssx\Wiretap\Blocklist;

use Ssx\Wiretap\Contract\BlocklistProvider;

/**
 * Curated pattern sets.
 *
 * The payment-gateways preset is enabled by default. Defaulting it off would
 * make the first cardholder-data incident a configuration oversight rather
 * than a decision someone took deliberately.
 *
 * The obvious objection is that capture then silently omits the very
 * integration someone is trying to debug. That is answered by visibility
 * rather than by weakening the default: `wiretap doctor` prints the active
 * patterns, their sources, and the per-host block counts, so an absent
 * request explains itself.
 *
 * This list is a starting point and is not exhaustive. No preset can know
 * which of *your* endpoints carry cardholder data; that remains the
 * integrating developer's responsibility.
 */
final readonly class PresetBlocklistProvider implements BlocklistProvider
{
    public const PAYMENT_GATEWAYS = 'payment-gateways';
    public const CLOUD_METADATA = 'cloud-metadata';

    /**
     * @var array<string, list<string>>
     */
    private const PRESETS = [
        self::PAYMENT_GATEWAYS => [
            '*.stripe.com',
            '*.adyen.com',
            '*.braintreegateway.com',
            '*.braintree-api.com',
            '*.paypal.com',
            '*.sandbox.paypal.com',
            '*.worldpay.com',
            '*.checkout.com',
            '*.opayo.co.uk',
            '*.sagepay.com',
            '*.klarna.com',
            '*.globalpay.com',
            '*.realexpayments.com',
            '*.cybersource.com',
            '*.mollie.com',
            '*.squareup.com',
            '*.gocardless.com',
        ],

        // Instance metadata endpoints hand out short-lived cloud credentials.
        // Capturing a response from one puts an IAM token in the log.
        self::CLOUD_METADATA => [
            '169.254.169.254',
            'metadata.google.internal',
            '100.100.100.200',
        ],
    ];

    /**
     * @param list<string> $presets
     */
    public function __construct(private array $presets = [self::PAYMENT_GATEWAYS])
    {
    }

    public static function all(): self
    {
        return new self(array_keys(self::PRESETS));
    }

    public function patterns(): iterable
    {
        foreach ($this->presets as $preset) {
            if (!isset(self::PRESETS[$preset])) {
                throw new \InvalidArgumentException(sprintf(
                    'Unknown blocklist preset "%s". Available: %s',
                    $preset,
                    implode(', ', array_keys(self::PRESETS)),
                ));
            }

            yield from self::PRESETS[$preset];
        }
    }

    public function name(): string
    {
        return 'preset:' . implode('+', $this->presets);
    }

    /**
     * @return list<string>
     */
    public static function available(): array
    {
        return array_keys(self::PRESETS);
    }
}
