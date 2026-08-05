<?php

declare(strict_types=1);

namespace Nvl\Auth\Actions\Rbac;

use Illuminate\Contracts\Auth\Authenticatable;
use Nvl\Auth\Enums\AuthFeature;
use Nvl\Auth\Enums\FeatureOperation;
use Nvl\Auth\Models\Permission;
use Nvl\Auth\Models\Role;
use Nvl\Auth\Results\RbacAnalytics;
use Nvl\Auth\Services\AuthModelRegistry;
use Nvl\Auth\Services\FeatureGate;
use Nvl\Auth\Services\ManagementAuthorizer;

/** Calculates bounded role, permission, and assignment aggregates. */
final readonly class ShowRbacAnalyticsAction
{
    /** Create the analytics use case. */
    public function __construct(
        private FeatureGate $features,
        private ManagementAuthorizer $authorization,
        private AuthModelRegistry $models,
    ) {}

    /** Return current package RBAC aggregates. */
    public function execute(Authenticatable $actor): RbacAnalytics
    {
        $this->features->assertAllowed(AuthFeature::Rbac, FeatureOperation::Read);
        $this->authorization->authorize($actor, 'nvl-auth.rbac.view');
        $roleClass = $this->models->roleClass();
        $permissionClass = $this->models->permissionClass();
        $roles = $roleClass::query()->withCount(['users', 'permissions'])->get();
        $permissions = $permissionClass::query()->withCount('users')->get();
        $largest = array_values($roles->sortByDesc('users_count')->take(10)->values()->map(static fn (Role $role): array => [
            'id' => $role->id,
            'name' => $role->name,
            'users_count' => $role->users_count ?? 0,
            'permissions_count' => $role->permissions_count ?? 0,
        ])->all());
        $roleAssignments = $roles->reduce(
            static fn (int $total, Role $role): int => $total + ($role->users_count ?? 0),
            0,
        );
        $directAssignments = $permissions->reduce(
            static fn (int $total, Permission $permission): int => $total + ($permission->users_count ?? 0),
            0,
        );

        return new RbacAnalytics(
            roles: $roles->count(),
            permissions: $permissions->count(),
            roleAssignments: $roleAssignments,
            directPermissionAssignments: $directAssignments,
            unassignedRoles: $roles->where('users_count', 0)->count(),
            largestRoles: $largest,
        );
    }
}
