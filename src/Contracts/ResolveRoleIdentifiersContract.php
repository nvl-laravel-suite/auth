<?php

declare(strict_types=1);

namespace Nvl\Auth\Contracts;

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Support\Collection;
use Nvl\Auth\Data\Display\RoleOptionData;

/**
 * Defines the resolve role identifiers use-case boundary.
 *
 * @api
 */
interface ResolveRoleIdentifiersContract
{
    /**
     * Resolve role identifiers in caller order without exposing models.
     *
     * @param  list<string>  $identifiers
     * @return Collection<int, RoleOptionData>
     */
    public function execute(Authenticatable $actor, array $identifiers): Collection;
}
