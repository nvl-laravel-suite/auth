<?php

declare(strict_types=1);

namespace Nvl\Auth\Contracts;

use Illuminate\Contracts\Auth\Authenticatable;

/**
 * Defines the list role hierarchy use-case boundary.
 *
 * @api
 */
interface ListRoleHierarchyContract
{
    /** @return list<array{id: string, name: string, display_name: string|null, priority: int, user_count: int, children: list<mixed>}> */
    public function execute(Authenticatable $actor): array;
}
