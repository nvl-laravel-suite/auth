<?php

declare(strict_types=1);

namespace Nvl\Auth\Contracts;

use Illuminate\Contracts\Auth\Authenticatable;
use Nvl\Auth\Models\TenantMembership;
use Nvl\Auth\ValueObjects\SystemMutationContext;

/**
 * Defines the revoke membership use-case boundary.
 *
 * @api
 */
interface RevokeMembershipContract
{
    public function execute(Authenticatable|SystemMutationContext $authority, TenantMembership|string $membership, int $expectedRevision): TenantMembership;
}
