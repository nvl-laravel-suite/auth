<?php

declare(strict_types=1);

namespace Nvl\Auth\Contracts;

use Illuminate\Contracts\Auth\Authenticatable;
use Nvl\Tenancy\ValueObjects\TenantId;

/** Declares authoritative tenant ownership lookup for persisted API tokens. */
interface TenantBoundApiTokenManager
{
    public function tenantForToken(Authenticatable $subject, string $tokenId): ?TenantId;
}
