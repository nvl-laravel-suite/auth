<?php

declare(strict_types=1);

namespace Nvl\Auth\Contracts;

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Contracts\Pagination\LengthAwarePaginator;
use Nvl\Auth\Data\Display\PermissionListItemData;
use Nvl\Auth\Data\Queries\PermissionIndexQueryData;

/**
 * Defines the list permission catalog use-case boundary.
 *
 * @api
 */
interface ListPermissionCatalogContract
{
    /**
     * Return a bounded paginator whose items are package DTOs, never models.
     *
     * @return LengthAwarePaginator<int, PermissionListItemData>
     */
    public function execute(
        Authenticatable $actor,
        PermissionIndexQueryData $data,
    ): LengthAwarePaginator;
}
