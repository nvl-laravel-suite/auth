<?php

declare(strict_types=1);

namespace Nvl\Auth\Services;

use Nvl\Auth\Models\Permission;
use Nvl\Auth\Models\Role;

/**
 * Applies contributed permission catalogs and role templates to Spatie storage.
 */
final readonly class RbacSynchronizer
{
    /**
     * Create the RBAC synchronization service.
     */
    public function __construct(
        private PermissionCatalogRegistry $catalog,
        private RoleTemplateRegistry $templates,
        private AuthModelRegistry $models,
    ) {}

    /**
     * Create missing catalog permissions and return the created count.
     */
    public function synchronizePermissions(string $guard): int
    {
        $created = 0;
        $permissionClass = $this->models->permissionClass();

        foreach ($this->catalog->permissions() as $permission) {
            $exists = $permissionClass::query()
                ->where('name', $permission)
                ->where('guard_name', $guard)
                ->exists();
            $model = $permissionClass::findOrCreate($permission, $guard);

            if ($model instanceof Permission && ! $model->is_system) {
                $model->forceFill(['is_system' => true])->save();
            }
            $created += $exists ? 0 : 1;
        }

        return $created;
    }

    /**
     * Synchronize contributed role templates and return the role count.
     */
    public function synchronizeRoles(string $guard): int
    {
        $roles = $this->templates->roles();
        $roleClass = $this->models->roleClass();
        $permissionClass = $this->models->permissionClass();

        foreach ($roles as $name => $permissions) {
            $role = $roleClass::findOrCreate($name, $guard);

            if ($role instanceof Role && ! $role->is_system) {
                $role->forceFill(['is_system' => true])->save();
            }
            $permissionModels = [];

            foreach ($permissions as $permission) {
                $permissionModels[] = $permissionClass::findOrCreate($permission, $guard);
            }

            $role->syncPermissions($permissionModels);
        }

        return count($roles);
    }
}
