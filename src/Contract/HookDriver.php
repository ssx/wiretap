<?php

declare(strict_types=1);

namespace Ssx\Wiretap\Contract;

/**
 * Whatever mechanism installs the function hooks.
 *
 * Only one implementation ships — the one backed by ext-opentelemetry, in
 * ssx/wiretap-auto. The interface exists so that moving to a different
 * hooking extension later is a contained change rather than an architectural
 * one, and so the core has no hard dependency on any extension.
 */
interface HookDriver
{
    /**
     * Whether this driver can run in the current process.
     */
    public function isAvailable(): bool;

    /**
     * Install the hooks. Must be idempotent — calling it twice registers one
     * set of hooks, not two.
     */
    public function register(): void;

    public function isRegistered(): bool;

    /**
     * Human-readable diagnostics for `wiretap doctor`.
     *
     * @return array<string, string>
     */
    public function diagnostics(): array;
}
