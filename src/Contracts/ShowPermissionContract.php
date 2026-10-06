<?php

declare(strict_types=1);

namespace Nvl\Auth\Contracts;

use Illuminate\Contracts\Auth\Authenticatable;
use Nvl\Auth\Models\Permission;

/**
 * Defines the show permission use-case boundary.
 *
 * @api
 */
interface ShowPermissionContract
{
    /** Return one permission. */
    public function execute(Authenticatable $actor, Permission|string $permission): Permission;
}
