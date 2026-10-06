<?php

declare(strict_types=1);

namespace Nvl\Auth\Contracts;

use Nvl\Auth\Models\TenantMembership;
use Nvl\Auth\ValueObjects\SubjectReference;
use Nvl\Auth\ValueObjects\SystemMutationContext;

/**
 * Defines the provision tenant owner use-case boundary.
 *
 * @api
 */
interface ProvisionTenantOwnerContract
{
    public function execute(SystemMutationContext $authority, SubjectReference $subject): TenantMembership;
}
