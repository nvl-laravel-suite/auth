<?php

declare(strict_types=1);

namespace Nvl\Auth\Contracts;

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Support\Collection;
use Nvl\Auth\Data\Display\PermissionOptionData;

/**
 * Defines the list permission options use-case boundary.
 *
 * @api
 */
interface ListPermissionOptionsContract
{
    /**
     * Return minimal permission projections without exposing Eloquent models.
     *
     * @return Collection<int, PermissionOptionData>
     */
    public function execute(
        Authenticatable $actor,
        ?string $search = null,
        ?string $group = null,
        ?int $limit = null,
    ): Collection;
}
