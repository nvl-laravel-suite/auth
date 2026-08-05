<?php

declare(strict_types=1);

namespace Nvl\Auth\Tests\Fixtures;

use Illuminate\Contracts\Auth\Authenticatable;
use Nvl\Auth\Contracts\AuthManagementAccess;

/**
 * Authorizes package management operations in integration tests.
 */
final class AllowAllManagementAccess implements AuthManagementAccess
{
    /**
     * Authorize every fixture actor.
     */
    public function allows(Authenticatable $actor, string $ability, mixed $target = null): bool
    {
        return true;
    }
}
