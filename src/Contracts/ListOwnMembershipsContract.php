<?php

declare(strict_types=1);

namespace Nvl\Auth\Contracts;

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Support\Collection;

/**
 * Defines the list own memberships use-case boundary.
 *
 * @api
 */
interface ListOwnMembershipsContract
{
    /** @return Collection<int, array{tenant_id: string, membership_id: string, status: 'active'|'suspended'|'revoked', revision: int}> */
    public function execute(Authenticatable $subject): Collection;
}
