<?php

declare(strict_types=1);

namespace Nvl\Auth\Contracts;

use Illuminate\Contracts\Auth\Authenticatable;
use Nvl\Auth\Data\Mutations\SyncUserPermissionsData;
use Nvl\Auth\ValueObjects\SystemMutationContext;

/**
 * Defines the sync user permissions use-case boundary.
 *
 * @api
 */
interface SyncUserPermissionsContract
{
    /** Synchronize one validated direct permission assignment atomically. */
    public function execute(
        Authenticatable|SystemMutationContext $authority,
        Authenticatable|string $user,
        SyncUserPermissionsData $data,
    ): Authenticatable;
}
