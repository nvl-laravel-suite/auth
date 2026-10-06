<?php

declare(strict_types=1);

namespace Nvl\Auth\Tests\Fixtures;

use Illuminate\Contracts\Auth\Authenticatable;
use Nvl\Support\Tenancy\Contracts\TenantMembershipAccess;
use Nvl\Support\Tenancy\ValueObjects\TenantId;

/** A genuine host membership adapter unrelated to Core's disabled fallback. */
final class AuthHostMembershipAccess implements TenantMembershipAccess
{
    public function assertMember(Authenticatable $actor, TenantId $tenant): void {}
}
