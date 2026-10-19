<?php

declare(strict_types=1);

namespace Nvl\Auth\Contracts;

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Contracts\Pagination\LengthAwarePaginator;
use Nvl\Auth\Models\Membership;

/**
 * Defines the list memberships use-case boundary.
 *
 * @api
 */
interface ListMembershipsContract
{
    /** @return LengthAwarePaginator<int, Membership> */
    public function execute(Authenticatable $actor, ?string $search = null, int $perPage = 25): LengthAwarePaginator;
}
