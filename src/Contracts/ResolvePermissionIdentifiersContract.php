<?php

declare(strict_types=1);

namespace Nvl\Auth\Contracts;

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Support\Collection;
use Nvl\Auth\Data\Display\PermissionOptionData;

/**
 * Defines the resolve permission identifiers use-case boundary.
 *
 * @api
 */
interface ResolvePermissionIdentifiersContract
{
    /**
     * Resolve permission identifiers in caller order without exposing models.
     *
     * @param  list<string>  $identifiers
     * @return Collection<int, PermissionOptionData>
     */
    public function execute(Authenticatable $actor, array $identifiers): Collection;
}
