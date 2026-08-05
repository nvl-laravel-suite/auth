<?php

declare(strict_types=1);

namespace Nvl\Auth\Services;

use Nvl\Auth\Models\Permission;
use Nvl\Auth\Models\Role;

/**
 * Resolves configured package RBAC entities without controller-owned queries.
 */
final readonly class RbacEntityLocator
{
    /**
     * Create the RBAC entity locator.
     */
    public function __construct(private AuthModelRegistry $models) {}

    /**
     * Resolve a role model or identifier.
     */
    public function role(Role|string $role): Role
    {
        if ($role instanceof Role) {
            return $role;
        }

        $class = $this->models->roleClass();

        return $class::query()->findOrFail($role);
    }

    /**
     * Resolve a permission model or identifier.
     */
    public function permission(Permission|string $permission): Permission
    {
        if ($permission instanceof Permission) {
            return $permission;
        }

        $class = $this->models->permissionClass();

        return $class::query()->findOrFail($permission);
    }
}
