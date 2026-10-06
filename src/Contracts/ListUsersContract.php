<?php

declare(strict_types=1);

namespace Nvl\Auth\Contracts;

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Contracts\Pagination\LengthAwarePaginator;
use Nvl\Auth\Models\User;

/**
 * Defines the list users use-case boundary.
 *
 * @api
 */
interface ListUsersContract
{
    /**
     * Return a paginated principal inventory.
     *
     * @return LengthAwarePaginator<int, User>
     */
    public function execute(
        Authenticatable $actor,
        ?string $search = null,
        ?bool $active = null,
        string $trashed = 'without',
        ?string $role = null,
        int $perPage = 25,
    ): LengthAwarePaginator;
}
