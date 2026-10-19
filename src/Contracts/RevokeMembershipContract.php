<?php

declare(strict_types=1);

namespace Nvl\Auth\Contracts;

use Illuminate\Contracts\Auth\Authenticatable;
use Nvl\Auth\Models\Membership;
use Nvl\Auth\ValueObjects\SystemMutationContext;

/**
 * Defines the revoke membership use-case boundary.
 *
 * @api
 */
interface RevokeMembershipContract
{
    public function execute(Authenticatable|SystemMutationContext $authority, Membership|string $membership, int $expectedRevision): Membership;
}
