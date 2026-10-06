<?php

declare(strict_types=1);

namespace Nvl\Auth\Contracts;

use Illuminate\Contracts\Auth\Authenticatable;
use Nvl\Auth\Data\Mutations\StorePermissionData;
use Nvl\Auth\Models\Permission;

/**
 * Defines the create permission use-case boundary.
 *
 * @api
 */
interface CreatePermissionContract
{
    /** Persist one permission. */
    public function execute(Authenticatable $actor, StorePermissionData $data): Permission;
}
