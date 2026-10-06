<?php

declare(strict_types=1);

namespace Nvl\Auth\Contracts;

use Illuminate\Contracts\Auth\Authenticatable;
use Nvl\Auth\Data\Mutations\StoreUserData;
use Nvl\Auth\Models\User;

/**
 * Defines the create user use-case boundary.
 *
 * @api
 */
interface CreateUserContract
{
    /** Persist a principal and optional RBAC assignment atomically. */
    public function execute(Authenticatable $actor, StoreUserData $data): User;
}
