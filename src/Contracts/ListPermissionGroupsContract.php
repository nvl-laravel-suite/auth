<?php

declare(strict_types=1);

namespace Nvl\Auth\Contracts;

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Support\Collection;
use Nvl\Auth\Data\Display\PermissionGroupData;

/**
 * Defines the list permission groups use-case boundary.
 *
 * @api
 */
interface ListPermissionGroupsContract
{
    /**
     * Aggregate raw database groups in one query and normalize them in memory.
     *
     * @return Collection<int, PermissionGroupData>
     */
    public function execute(Authenticatable $actor): Collection;
}
