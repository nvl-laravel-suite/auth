<?php

declare(strict_types=1);

namespace Nvl\Auth\Services;

use Illuminate\Database\Connection;
use LogicException;
use Nvl\Auth\Exceptions\AuthException;
use Nvl\Auth\Models\Permission;
use Nvl\Auth\Models\Role;

/**
 * Applies contributed permission catalogs and role templates to Spatie storage.
 *
 * @internal
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

    /** Resolve the single storage source required by role-permission mutations. */
    public function roleConnection(): Connection
    {
        $roleClass = $this->models->roleClass();
        $permissionClass = $this->models->permissionClass();
        $connection = (new $roleClass)->getConnection();
        if ($connection !== (new $permissionClass)->getConnection()) {
            throw AuthException::invalidConfiguration('RBAC roles and permissions must use the same connection.');
        }

        return $connection;
    }

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
        $this->roleConnection();
        $roles = $this->templates->roles();
        $roleClass = $this->models->roleClass();
        $permissionClass = $this->models->permissionClass();

        foreach ($roles as $template) {
            $parent = $template->parentRole !== null
                ? $roleClass::findOrCreate($template->parentRole, $guard)
                : null;
            $parentId = $parent?->getKey();

            if ($parentId !== null && ! is_string($parentId)) {
                throw new LogicException('Configured RBAC role identifiers must be strings.');
            }

            $mutation = $template->toMutation(parentId: $parentId);
            $role = $roleClass::findOrCreate($mutation['name'], $guard);

            if ($role instanceof Role) {
                $attributes = ['name' => $mutation['name'], 'display_name' => $mutation['displayName'], 'description' => $mutation['description'], 'parent_id' => $mutation['parentId'], 'priority' => $mutation['priority'], 'system' => $mutation['system'], 'metadata' => $mutation['metadata']];
                $attributes['is_system'] = $attributes['system'];
                unset($attributes['system']);
                $role->fill($attributes)->save();
            }
            $permissionModels = [];

            foreach ($mutation['permissions'] as $permission) {
                $permissionModels[] = $permissionClass::findOrCreate($permission, $guard);
            }

            $role->syncPermissions($permissionModels);
        }

        return count($roles);
    }
}
