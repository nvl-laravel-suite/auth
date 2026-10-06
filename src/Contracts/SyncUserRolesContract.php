<?php

declare(strict_types=1);

namespace Nvl\Auth\Contracts;

use Illuminate\Contracts\Auth\Authenticatable;
use Nvl\Auth\Data\Mutations\SyncUserRolesData;
use Nvl\Auth\ValueObjects\SystemMutationContext;

/**
 * Defines the sync user roles use-case boundary.
 *
 * @api
 */
interface SyncUserRolesContract
{
    /** Synchronize one validated role assignment atomically. */
    public function execute(
        Authenticatable|SystemMutationContext $authority,
        Authenticatable|string $user,
        SyncUserRolesData $data,
    ): Authenticatable;
}
