<?php

declare(strict_types=1);

namespace Nvl\Auth\Contracts;

use Illuminate\Contracts\Auth\Authenticatable;
use Nvl\Auth\Results\RbacSynchronizationResult;

/**
 * Defines the synchronize rbac use-case boundary.
 *
 * @api
 */
interface SynchronizeRbacContract
{
    /**
     * Synchronize permission catalogs and role templates in one transaction.
     */
    public function execute(Authenticatable $actor): RbacSynchronizationResult;
}
