<?php

declare(strict_types=1);

namespace Nvl\Auth\Contracts;

use Illuminate\Contracts\Auth\Authenticatable;

/**
 * Delegates package management authorization to the host application.
 */
interface AuthManagementAccess
{
    /**
     * Determine whether an actor may perform one package management ability.
     */
    public function allows(
        Authenticatable $actor,
        string $ability,
        mixed $target = null,
    ): bool;
}
