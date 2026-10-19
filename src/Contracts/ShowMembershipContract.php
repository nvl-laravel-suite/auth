<?php

declare(strict_types=1);

namespace Nvl\Auth\Contracts;

use Illuminate\Contracts\Auth\Authenticatable;
use Nvl\Auth\Data\Display\TenantMembershipData;
use Nvl\Auth\Models\Membership;

/**
 * Defines the show membership use-case boundary.
 *
 * @api
 */
interface ShowMembershipContract
{
    public function execute(Authenticatable $actor, Membership|string $membership): TenantMembershipData;
}
