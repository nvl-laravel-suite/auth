<?php

declare(strict_types=1);

namespace Nvl\Auth\Contracts;

use Illuminate\Contracts\Auth\Authenticatable;
use Nvl\Auth\Data\Mutations\UpdateUserStatusData;
use Nvl\Auth\Models\User;
use Nvl\Auth\ValueObjects\SystemMutationContext;

/**
 * Defines the set user active use-case boundary.
 *
 * @api
 */
interface SetUserActiveContract
{
    /** Persist the principal activation state. */
    public function execute(
        Authenticatable|SystemMutationContext $authority,
        User|string $user,
        UpdateUserStatusData $data,
    ): User;
}
