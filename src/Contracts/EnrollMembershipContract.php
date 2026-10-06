<?php

declare(strict_types=1);

namespace Nvl\Auth\Contracts;

use Illuminate\Contracts\Auth\Authenticatable;
use Nvl\Auth\Data\Mutations\EnrollMembershipData;
use Nvl\Auth\Models\TenantMembership;
use Nvl\Auth\ValueObjects\SystemMutationContext;

/**
 * Defines the enroll membership use-case boundary.
 *
 * @api
 */
interface EnrollMembershipContract
{
    public function execute(Authenticatable|SystemMutationContext $authority, EnrollMembershipData $data): TenantMembership;
}
