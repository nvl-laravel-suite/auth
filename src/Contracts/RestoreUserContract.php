<?php

declare(strict_types=1);

namespace Nvl\Auth\Contracts;

use Illuminate\Contracts\Auth\Authenticatable;
use Nvl\Auth\Models\User;
use Nvl\Auth\ValueObjects\SystemMutationContext;

/**
 * Defines the restore user use-case boundary.
 *
 * @api
 */
interface RestoreUserContract
{
    /** Restore one principal without silently re-enabling it. */
    public function execute(Authenticatable|SystemMutationContext $authority, User|string $user): User;
}
