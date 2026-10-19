<?php

declare(strict_types=1);

namespace Nvl\Auth\Contracts;

use Illuminate\Contracts\Auth\Authenticatable;
use Nvl\Auth\Data\Mutations\TransferMembershipOwnershipData;
use Nvl\Auth\Models\Membership;
use Nvl\Auth\ValueObjects\SystemMutationContext;

/**
 * Defines the transfer membership ownership use-case boundary.
 *
 * @api
 */
interface TransferMembershipOwnershipContract
{
    public function execute(Authenticatable|SystemMutationContext $authority, Membership|string $membership, TransferMembershipOwnershipData $data): Membership;
}
