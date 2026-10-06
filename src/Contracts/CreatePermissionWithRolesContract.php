<?php

declare(strict_types=1);

namespace Nvl\Auth\Contracts;

use Illuminate\Contracts\Auth\Authenticatable;
use Nvl\Auth\Data\Mutations\StorePermissionData;
use Nvl\Auth\Models\Permission;

/**
 * Defines the create permission with roles use-case boundary.
 *
 * @api
 */
interface CreatePermissionWithRolesContract
{
    /**
     * Create one permission and attach all resolved roles in one transaction.
     *
     * @param  list<string>  $roleIdentifiers
     */
    public function execute(
        Authenticatable $actor,
        StorePermissionData $data,
        array $roleIdentifiers = [],
    ): Permission;
}
