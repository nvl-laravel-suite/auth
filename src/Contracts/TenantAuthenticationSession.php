<?php

declare(strict_types=1);

namespace Nvl\Auth\Contracts;

use Nvl\Auth\ValueObjects\PendingTenantAuthenticationIntent;

/** Stores server-only tenant intent state alongside Socialite's authoritative OAuth state. */
interface TenantAuthenticationSession
{
    public function authenticationFlowBinding(string $flow): string;

    public function storeAuthenticationIntent(string $flow, string $nonce): void;

    public function pullAuthenticationIntent(string $flow): ?string;

    public function forgetAuthenticationFlowBinding(string $flow): void;

    public function storePendingTenantAuthenticationIntent(PendingTenantAuthenticationIntent $intent): void;

    public function pendingTenantAuthenticationIntent(): ?PendingTenantAuthenticationIntent;

    public function forgetPendingTenantAuthenticationIntent(): void;
}
