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
 * The claim travels as a curl option on the handle itself, because that is
 * the one thing that reaches the hooks on every hop: Guzzle copies its request
 * options through redirects and retries, and Symfony's retry layer re-issues
 * the same options. It is not a real curl option. ext-curl rejects it with a
 * ValueError, so it must never reach curl: the hooks strip it before curl
 * sees it, and a bridge only sends it once the hooks have said they will.
 *
 * That is what the honoured flag is for. It is set by wiretap-auto after its
 * hooks are installed and it has proved they strip the option. When the
 * extension is missing, auto is disabled, or auto is not installed at all, it
 * stays false and bridges add nothing, so their curl options are exactly what
 * they would have been without this class.
 *
 * This class has no behaviour of its own.
 */
final class TransferClaim
{
    /**
     * The option key a bridge adds to a transfer's curl options.
     *
     * Negative, because every libcurl option id is a positive offset from one
     * of the CURLOPTTYPE_* bases, and the only negative option PHP defines
     * itself is CURLOPT_SAFE_UPLOAD (-1). This is -0x77697265, "wire".
     */
    public const OPTION = -2003398245;

    private static bool $honoured = false;

    /**
     * Called by the curl hooks once they strip the option. Not for bridges.
     */
    public static function honour(): void
    {
        self::$honoured = true;
    }

    /**
     * Whether a bridge may add the option. False means send nothing extra.
     */
    public static function isHonoured(): bool
    {
        return self::$honoured;
    }

    /**
     * For tests. Deliberately not called by Wiretap::reset(): the hooks that
     * strip the option are process-wide and survive a reset, so the flag that
     * describes them should too.
     */
    public static function reset(): void
    {
        self::$honoured = false;
    }
}
