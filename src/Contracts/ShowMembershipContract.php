<?php

declare(strict_types=1);

namespace Nvl\Auth\Contracts;

use Illuminate\Contracts\Auth\Authenticatable;
use Nvl\Auth\Data\Display\TenantMembershipData;
use Nvl\Auth\Models\TenantMembership;

/**
 * Defines the show membership use-case boundary.
 *
 * @api
 */
interface ShowMembershipContract
{
    public function execute(Authenticatable $actor, TenantMembership|string $membership): TenantMembershipData;
}
