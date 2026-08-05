<?php

declare(strict_types=1);

namespace Nvl\Auth\Services;

use Illuminate\Contracts\Auth\Access\Gate;
use Illuminate\Contracts\Auth\Authenticatable;
use Nvl\Auth\Contracts\AuthManagementAccess;

/**
 * Uses host-defined Laravel Gate abilities for Auth management access.
 */
final readonly class LaravelGateAuthManagementAccess implements AuthManagementAccess
{
    /**
     * Create the Laravel Gate management adapter.
     */
    public function __construct(private Gate $gate) {}

    /**
     * Determine whether the host grants the requested ability.
     */
    public function allows(
        Authenticatable $actor,
        string $ability,
        mixed $target = null,
    ): bool {
        $superAdminRole = config('nvl-auth.features.rbac.settings.super_admin_role', 'super-admin');

        if (is_string($superAdminRole)
            && trim($superAdminRole) !== ''
            && method_exists($actor, 'hasRole')
            && $actor->hasRole(trim($superAdminRole))) {
            return true;
        }

        return $this->gate->forUser($actor)->allows($ability, $target === null ? [] : [$target]);
    }
}
