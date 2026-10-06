<?php

declare(strict_types=1);

namespace Nvl\Auth\Contracts;

use Illuminate\Contracts\Auth\Authenticatable;
use Nvl\Auth\Data\Mutations\StoreRoleData;
use Nvl\Auth\Models\Role;

/**
 * Defines the create role use-case boundary.
 *
 * @api
 */
interface CreateRoleContract
{
    /** Persist one role. */
    public function execute(Authenticatable $actor, StoreRoleData $data): Role;
}
