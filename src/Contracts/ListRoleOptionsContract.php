<?php

declare(strict_types=1);

namespace Nvl\Auth\Contracts;

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Support\Collection;
use Nvl\Auth\Data\Display\RoleOptionData;

/**
 * Defines the list role options use-case boundary.
 *
 * @api
 */
interface ListRoleOptionsContract
{
    /**
     * Return minimal role projections without exposing Eloquent models.
     *
     * @return Collection<int, RoleOptionData>
     */
    public function execute(
        Authenticatable $actor,
        ?string $search = null,
        ?int $limit = null,
    ): Collection;
}
