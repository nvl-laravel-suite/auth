<?php

declare(strict_types=1);

namespace Nvl\Auth\Contracts;

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Contracts\Pagination\LengthAwarePaginator;
use Nvl\Auth\Data\Display\RoleListItemData;

/**
 * Defines the list roles use-case boundary.
 *
 * @api
 */
interface ListRolesContract
{
    /** @return LengthAwarePaginator<int, RoleListItemData> */
    public function execute(Authenticatable $actor, ?string $search = null, int $perPage = 25): LengthAwarePaginator;
}
