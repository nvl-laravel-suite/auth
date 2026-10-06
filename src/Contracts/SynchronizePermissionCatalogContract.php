<?php

declare(strict_types=1);

namespace Nvl\Auth\Contracts;

use Illuminate\Contracts\Auth\Authenticatable;

/**
 * Defines the synchronize permission catalog use-case boundary.
 *
 * @api
 */
interface SynchronizePermissionCatalogContract
{
    /**
     * Create missing permissions without deleting host-owned records.
     */
    public function execute(Authenticatable $actor): int;
}
