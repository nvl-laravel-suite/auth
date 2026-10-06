<?php

declare(strict_types=1);

namespace Nvl\Auth\Contracts;

use Illuminate\Contracts\Auth\Authenticatable;
use Nvl\Auth\Data\Mutations\UpdateMembershipStatusData;
use Nvl\Auth\Models\TenantMembership;
use Nvl\Auth\ValueObjects\SystemMutationContext;

/**
 * Defines the set membership status use-case boundary.
 *
 * @api
 */
interface SetMembershipStatusContract
{
    public function execute(Authenticatable|SystemMutationContext $authority, TenantMembership|string $membership, UpdateMembershipStatusData $data): TenantMembership;
}
