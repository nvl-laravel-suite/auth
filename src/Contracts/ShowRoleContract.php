<?php

declare(strict_types=1);

namespace Nvl\Auth\Contracts;

use Illuminate\Contracts\Auth\Authenticatable;
use Nvl\Auth\Models\Role;

/**
 * Defines the show role use-case boundary.
 *
 * @api
 */
interface ShowRoleContract
{
    /** Return one role. */
    public function execute(Authenticatable $actor, Role|string $role): Role;
}
