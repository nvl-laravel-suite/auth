<?php

declare(strict_types=1);

namespace Nvl\Auth\Contracts;

use Illuminate\Contracts\Auth\Authenticatable;
use Nvl\Auth\Models\Role;

/**
 * Defines the sync role permissions use-case boundary.
 *
 * @api
 */
interface SyncRolePermissionsContract
{
    /**
     * Synchronize a bounded set of permission IDs or names atomically.
     *
     * @param  list<string>  $permissionIdentifiers
     */
    public function execute(
        Authenticatable $actor,
        Role|string $role,
        array $permissionIdentifiers,
    ): Role;
}
