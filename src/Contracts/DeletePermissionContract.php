<?php

declare(strict_types=1);

namespace Nvl\Auth\Contracts;

use Illuminate\Contracts\Auth\Authenticatable;
use Nvl\Auth\Models\Permission;

/**
 * Defines the delete permission use-case boundary.
 *
 * @api
 */
interface DeletePermissionContract
{
    /** Delete one permission. */
    public function execute(Authenticatable $actor, Permission|string $permission): bool;
}
