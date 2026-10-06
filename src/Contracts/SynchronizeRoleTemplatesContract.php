<?php

declare(strict_types=1);

namespace Nvl\Auth\Contracts;

use Illuminate\Contracts\Auth\Authenticatable;

/**
 * Defines the synchronize role templates use-case boundary.
 *
 * @api
 */
interface SynchronizeRoleTemplatesContract
{
    /**
     * Synchronize every configured role template and return the role count.
     */
    public function execute(Authenticatable $actor): int;
}
