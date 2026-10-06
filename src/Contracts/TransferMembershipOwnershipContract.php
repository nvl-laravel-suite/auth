<?php

declare(strict_types=1);

namespace Nvl\Auth\Contracts;

use Illuminate\Contracts\Auth\Authenticatable;
use Nvl\Auth\Data\Mutations\TransferMembershipOwnershipData;
use Nvl\Auth\Models\TenantMembership;
use Nvl\Auth\ValueObjects\SystemMutationContext;

/**
 * Defines the transfer membership ownership use-case boundary.
 *
 * @api
 */
interface TransferMembershipOwnershipContract
{
    public function execute(Authenticatable|SystemMutationContext $authority, TenantMembership|string $membership, TransferMembershipOwnershipData $data): TenantMembership;
}
