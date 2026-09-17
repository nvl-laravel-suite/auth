<?php

declare(strict_types=1);

namespace Nvl\Auth\Actions\Memberships;

use Illuminate\Contracts\Auth\Authenticatable;
use Nvl\Auth\Data\Mutations\UpdateMembershipStatusData;
use Nvl\Auth\Models\TenantMembership;
use Nvl\Auth\Services\MembershipMutator;
use Nvl\Auth\ValueObjects\SystemMutationContext;

/** Applies one optimistic membership status transition. */
final readonly class SetMembershipStatusAction
{
    public function __construct(private MembershipMutator $mutator) {}

    public function execute(Authenticatable|SystemMutationContext $authority, TenantMembership|string $membership, UpdateMembershipStatusData $data): TenantMembership
    {
        return $this->mutator->setStatus($authority, $membership, $data->status, $data->expectedRevision);
    }
}
