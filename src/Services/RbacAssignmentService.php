<?php

declare(strict_types=1);

namespace Nvl\Auth\Services;

use Illuminate\Support\Collection;
use Nvl\Auth\Exceptions\AuthException;
use Nvl\Auth\Models\Permission;
use Nvl\Auth\Models\Role;
use Spatie\Permission\PermissionRegistrar;

/**
 * Resolves and mutates package-owned role-permission assignments.
 *
 * @internal
 */
final readonly class RbacAssignmentService
{
    /** Create the role-permission assignment service. */
    public function __construct(
        private RbacEntityLocator $entities,
        private AuthModelRegistry $models,
        private AuthConfiguration $configuration,
        private PermissionRegistrar $registrar,
    ) {}

    /** Resolve the connection used by one role assignment transaction. */
    public function roleConnectionName(Role|string $role): ?string
    {
        if ($role instanceof Role) {
            return $role->getConnectionName();
        }

        $class = $this->models->roleClass();

        return (new $class)->getConnectionName();
    }

    /**
     * Add permissions without removing existing role assignments.
     *
     * @param  list<string>  $permissionIdentifiers
     * @return array{role: Role, permissionIds: list<string>, permissionNames: list<string>}
     */
    public function add(Role|string $role, array $permissionIdentifiers): array
    {
        $role = $this->resolveRole($role);
        $permissions = $this->canonicalPermissions($permissionIdentifiers);
        $permissionIds = $this->permissionIds($permissions);

        $role->permissions()->syncWithoutDetaching($permissionIds);

        return [
            'role' => $this->refreshRole($role),
            'permissionIds' => $permissionIds,
            'permissionNames' => $this->permissionNames($permissions),
        ];
    }

    /**
     * Replace all permissions assigned to one role.
     *
     * @param  list<string>  $permissionIdentifiers
     * @return array{role: Role, permissionIds: list<string>, permissionNames: list<string>}
     */
    public function synchronize(Role|string $role, array $permissionIdentifiers): array
    {
        $role = $this->resolveRole($role);
        $permissions = $this->canonicalPermissions($permissionIdentifiers);
        $permissionIds = $this->permissionIds($permissions);

        $role->permissions()->sync($permissionIds);

        return [
            'role' => $this->refreshRole($role),
            'permissionIds' => $permissionIds,
            'permissionNames' => $this->permissionNames($permissions),
        ];
    }

    /**
     * Attach one newly created permission to resolved roles.
     *
     * @param  list<string>  $roleIdentifiers
     * @return array{permission: Permission, roleIds: list<string>, roleNames: list<string>}
     */
    public function attachPermissionToRoles(Permission $permission, array $roleIdentifiers): array
    {
        $roles = $this->canonicalRoles($roleIdentifiers);
        $roleIds = $this->roleIds($roles);

        $permission->roles()->syncWithoutDetaching($roleIds);

        return [
            'permission' => $this->refreshPermission($permission),
            'roleIds' => $roleIds,
            'roleNames' => $this->roleNames($roles),
        ];
    }

    /** Clear Spatie's global permission map after a durable assignment change. */
    public function clearPermissionCache(): void
    {
        $this->registrar->forgetCachedPermissions();
    }

    /** Resolve one role while enforcing the configured model and guard. */
    private function resolveRole(Role|string $role): Role
    {
        if (is_string($role)) {
            /** @var Role $resolved */
            $resolved = $this->entities->rolesByIdentifiers([$role])->sole();

            return $resolved;
        }

        $class = $this->models->roleClass();
        $guard = $this->configuration->string('features.rbac.settings.guard', 'web');

        if (! $role instanceof $class || ! $role->exists || $role->guard_name !== $guard) {
            throw new AuthException(
                'role_identifier_not_found',
                'The requested role identifier was not found for the configured guard.',
            );
        }

        return $role;
    }

    /**
     * Resolve permissions and sort them by canonical name and ID.
     *
     * @param  list<string>  $identifiers
     * @return Collection<int, Permission>
     */
    private function canonicalPermissions(array $identifiers): Collection
    {
        return $this->entities
            ->permissionsByIdentifiers($identifiers)
            ->sortBy([
                static fn (Permission $left, Permission $right): int => $left->name <=> $right->name,
                static fn (Permission $left, Permission $right): int => $left->id <=> $right->id,
            ])
            ->values();
    }

    /**
     * Resolve roles and sort them by canonical name and ID.
     *
     * @param  list<string>  $identifiers
     * @return Collection<int, Role>
     */
    private function canonicalRoles(array $identifiers): Collection
    {
        return $this->entities
            ->rolesByIdentifiers($identifiers)
            ->sortBy([
                static fn (Role $left, Role $right): int => $left->name <=> $right->name,
                static fn (Role $left, Role $right): int => $left->id <=> $right->id,
            ])
            ->values();
    }

    /** Return a role with a deterministic permission relation. */
    private function refreshRole(Role $role): Role
    {
        $role = $role->refresh();
        $relation = $role->permissions();
        $table = $relation->getRelated()->getTable();
        $role->setRelation('permissions', $relation->orderBy("{$table}.name")->orderBy("{$table}.id")->get());

        return $role;
    }

    /** Return a permission with a deterministic role relation. */
    private function refreshPermission(Permission $permission): Permission
    {
        $permission = $permission->refresh();
        $relation = $permission->roles();
        $table = $relation->getRelated()->getTable();
        $permission->setRelation('roles', $relation->orderBy("{$table}.name")->orderBy("{$table}.id")->get());

        return $permission;
    }

    /**
     * @param  Collection<int, Permission>  $permissions
     * @return list<string>
     */
    private function permissionIds(Collection $permissions): array
    {
        $identifiers = [];

        foreach ($permissions as $permission) {
            $identifiers[] = $permission->id;
        }

        return $identifiers;
    }

    /**
     * @param  Collection<int, Permission>  $permissions
     * @return list<string>
     */
    private function permissionNames(Collection $permissions): array
    {
        $names = [];

        foreach ($permissions as $permission) {
            $names[] = $permission->name;
        }

        return $names;
    }

    /**
     * @param  Collection<int, Role>  $roles
     * @return list<string>
     */
    private function roleIds(Collection $roles): array
    {
        $identifiers = [];

        foreach ($roles as $role) {
            $identifiers[] = $role->id;
        }

        return $identifiers;
    }

    /**
     * @param  Collection<int, Role>  $roles
     * @return list<string>
     */
    private function roleNames(Collection $roles): array
    {
        $names = [];

        foreach ($roles as $role) {
            $names[] = $role->name;
        }

        return $names;
    }
}
