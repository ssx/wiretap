<?php

declare(strict_types=1);

namespace Ssx\Wiretap;

/**
 * Lets a bridge tell the curl hooks "this transfer is mine".
 *
 * A bridge (Guzzle middleware, the Symfony decorator) and ssx/wiretap-auto's
 * curl hooks can both see the same transfer. Run together, every call was
 * recorded twice: once by the bridge, with bodies, and once by the hooks, with
 * no link between the two. The bridge's record is the better one, so the
 * bridge claims the transfer and the hooks stand aside.
 *
 * The claim is a request option set to true: `$options[KEY]` on a Guzzle
 * request, `$options['extra'][KEY]` on a Symfony one. Request options are
 * what reaches every hop, because Guzzle copies them through its redirect and
 * retry middleware and Symfony's retry layer re-issues them. wiretap-auto
 * reads the option where each client turns a request into a curl handle, and
 * records nothing for that handle.
 *
 * It is deliberately not a curl option. An unknown key in Guzzle's `curl`
 * option raises a deprecation from Guzzle 7.12 and will be rejected by 8.0,
 * and ext-curl throws a ValueError for it. A request option neither client
 * recognises is ignored by both, and never reaches curl.
 *
 * Bridges add it only when the hooks have said they read it: honour() is
 * called by wiretap-auto once those hooks are installed. Without the
 * extension, with auto disabled or not installed at all, it stays false and
 * a bridge's request options are exactly what they would have been without
 * this class.
 *
 * This class has no behaviour of its own.
 */
final class TransferClaim
{
    /**
     * The request option a bridge sets to true on a transfer it records.
     */
    public const KEY = 'wiretap_claimed';

    private static bool $honoured = false;

    /**
     * Called by the curl hooks once they read the claim. Not for bridges.
     */
    public static function honour(): void
    {
        self::$honoured = true;
    }

    /**
     * Whether a bridge may add the claim. False means add nothing.
     */
    public static function isHonoured(): bool
    {
        return self::$honoured;
    }

    /**
     * For tests. Deliberately not called by Wiretap::reset(): the hooks that
     * read the claim are process-wide and survive a reset, so the flag that
     * describes them should too.
     */
    public static function reset(): void
    {
        self::$honoured = false;
    }
}
