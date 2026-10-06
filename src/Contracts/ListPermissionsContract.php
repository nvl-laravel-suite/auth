<?php

declare(strict_types=1);

namespace Nvl\Auth\Contracts;

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Contracts\Pagination\LengthAwarePaginator;
use Nvl\Auth\Data\Display\PermissionListItemData;

/**
 * Defines the list permissions use-case boundary.
 *
 * @api
 */
interface ListPermissionsContract
{
    /** @return LengthAwarePaginator<int, PermissionListItemData> */
    public function execute(Authenticatable $actor, ?string $search = null, ?string $group = null, int $perPage = 25): LengthAwarePaginator;
}
