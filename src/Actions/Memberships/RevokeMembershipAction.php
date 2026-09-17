<?php

declare(strict_types=1);

namespace Nvl\Auth\Actions\Memberships;

use Illuminate\Contracts\Auth\Authenticatable;
use Nvl\Auth\Models\TenantMembership;
use Nvl\Auth\Services\MembershipMutator;
use Nvl\Auth\ValueObjects\SystemMutationContext;

/** Revokes one tenant membership without mutating the global principal. */
final readonly class RevokeMembershipAction
{
    public function __construct(private MembershipMutator $mutator) {}

    public function execute(Authenticatable|SystemMutationContext $authority, TenantMembership|string $membership, int $expectedRevision): TenantMembership
    {
        return $this->mutator->revoke($authority, $membership, $expectedRevision);
    }
}
