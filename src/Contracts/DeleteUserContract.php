<?php

declare(strict_types=1);

namespace Nvl\Auth\Contracts;

use Illuminate\Contracts\Auth\Authenticatable;
use Nvl\Auth\Models\User;
use Nvl\Auth\ValueObjects\SystemMutationContext;

/**
 * Defines the delete user use-case boundary.
 *
 * @api
 */
interface DeleteUserContract
{
    /** Soft delete one principal. */
    public function execute(Authenticatable|SystemMutationContext $authority, User|string $user): bool;
}
