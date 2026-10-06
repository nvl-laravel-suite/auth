<?php

declare(strict_types=1);

namespace Nvl\Auth\Contracts;

use Illuminate\Contracts\Auth\Authenticatable;
use Nvl\Auth\Data\Mutations\UpdateUserData;
use Nvl\Auth\Models\User;

/**
 * Defines the update user use-case boundary.
 *
 * @api
 */
interface UpdateUserContract
{
    /** Persist a partial principal mutation. */
    public function execute(Authenticatable $actor, User|string $user, UpdateUserData $data): User;
}
