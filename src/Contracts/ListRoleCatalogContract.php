<?php

declare(strict_types=1);

namespace Nvl\Auth\Contracts;

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Contracts\Pagination\LengthAwarePaginator;
use Nvl\Auth\Data\Display\RoleListItemData;
use Nvl\Auth\Data\Queries\RoleIndexQueryData;

/**
 * Defines the list role catalog use-case boundary.
 *
 * @api
 */
interface ListRoleCatalogContract
{
    /**
     * Return a bounded paginator whose items are package DTOs, never models.
     *
     * @return LengthAwarePaginator<int, RoleListItemData>
     */
    public function execute(
        Authenticatable $actor,
        RoleIndexQueryData $data,
    ): LengthAwarePaginator;
}
