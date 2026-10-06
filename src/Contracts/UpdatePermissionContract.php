<?php

declare(strict_types=1);

namespace Nvl\Auth\Contracts;

use Illuminate\Contracts\Auth\Authenticatable;
use Nvl\Auth\Data\Mutations\UpdatePermissionData;
use Nvl\Auth\Models\Permission;

/**
 * Defines the update permission use-case boundary.
 *
 * @api
 */
interface UpdatePermissionContract
{
    /** Persist one permission mutation. */
    public function execute(Authenticatable $actor, Permission|string $permission, UpdatePermissionData $data): Permission;
}
