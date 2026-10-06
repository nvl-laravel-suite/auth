<?php

declare(strict_types=1);

namespace Nvl\Auth\Contracts;

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Support\Collection;
use Nvl\Auth\Data\Display\PermissionOptionData;

/**
 * Defines the suggest permissions use-case boundary.
 *
 * @api
 */
interface SuggestPermissionsContract
{
    /**
     * Return defaults for an empty search and no results for a one-character search.
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
