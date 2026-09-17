<?php

declare(strict_types=1);

namespace Nvl\Auth\Contracts;

use Nvl\Auth\ValueObjects\PendingTenantAuthenticationIntent;
use Nvl\Auth\ValueObjects\SubjectReference;
use Nvl\Tenancy\ValueObjects\TenantId;

/** Stores server-only tenant intent state alongside Socialite's authoritative OAuth state. */
interface TenantAuthenticationSession
{
    public function authenticationFlowBinding(string $flow): string;

    public function storeAuthenticationIntent(string $flow, string $nonce): void;

    public function pullAuthenticationIntent(string $flow): ?string;

    public function forgetAuthenticationFlowBinding(string $flow): void;

    public function storePendingTenantAuthenticationIntent(PendingTenantAuthenticationIntent $intent): void;

    public function pendingTenantAuthenticationIntent(
        TenantId $tenant,
        SubjectReference $subject,
    ): ?PendingTenantAuthenticationIntent;

    public function forgetPendingTenantAuthenticationIntent(PendingTenantAuthenticationIntent $intent): void;
}
