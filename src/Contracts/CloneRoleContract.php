<?php

declare(strict_types=1);

namespace Nvl\Auth\Contracts;

use Illuminate\Contracts\Auth\Authenticatable;
use Nvl\Auth\Models\Role;

/**
 * Defines the clone role use-case boundary.
 *
 * @api
 */
interface CloneRoleContract
{
    /** Clone one role. */
    public function execute(Authenticatable $actor, Role|string $role, string $name, ?string $displayName = null): Role;
}
