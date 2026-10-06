<?php

declare(strict_types=1);

namespace Nvl\Auth\Contracts;

use Illuminate\Contracts\Auth\Authenticatable;
use Nvl\Auth\Data\Mutations\UpdateRoleData;
use Nvl\Auth\Models\Role;

/**
 * Defines the update role use-case boundary.
 *
 * @api
 */
interface UpdateRoleContract
{
    /** Persist one role mutation. */
    public function execute(Authenticatable $actor, Role|string $role, UpdateRoleData $data): Role;
}
