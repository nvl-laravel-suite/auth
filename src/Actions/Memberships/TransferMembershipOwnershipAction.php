<?php

declare(strict_types=1);

namespace Nvl\Auth\Actions\Memberships;

use Illuminate\Contracts\Auth\Authenticatable;
use Nvl\Auth\Data\Mutations\TransferMembershipOwnershipData;
use Nvl\Auth\Models\TenantMembership;
use Nvl\Auth\Services\MembershipMutator;
use Nvl\Auth\ValueObjects\SystemMutationContext;

/** Transfers tenant ownership inside one locked transaction. */
final readonly class TransferMembershipOwnershipAction
{
    public function __construct(private MembershipMutator $mutator) {}

    public function execute(Authenticatable|SystemMutationContext $authority, TenantMembership|string $membership, TransferMembershipOwnershipData $data): TenantMembership
    {
        return $this->mutator->transfer($authority, $membership, $data);
    }
}
