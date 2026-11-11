<?php

declare(strict_types=1);

namespace Nvl\Auth\Services;

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Contracts\Container\Container;
use Illuminate\Database\Eloquent\Collection;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\Str;
use Nvl\Auth\Enums\AuthFeature;
use Nvl\Auth\Exceptions\AuthException;
use Nvl\Auth\Models\Permission;
use Nvl\Auth\Models\Role;
use Nvl\Support\Ownership\Contracts\OwnershipBoundary;
use Nvl\Support\Ownership\Contracts\OwnershipContext;

/**
 * Validates canonical tenant roles and fixed vocabulary permissions before assignment.
 *
 * @internal
 */
final readonly class OwnerMembershipAssignments
{
    public function __construct(private OwnershipBoundary $boundary,
        private OwnershipContext $ownership,
        private AuthModelRegistry $models,
        private AuthConfiguration $configuration,
        private Container $container,
    ) {}

    /**
     * @param  list<string>  $roles
     * @param  list<string>  $permissions
     */
    public function sync(Authenticatable $principal, array $roles, array $permissions): void
    {
        if (! $this->configuration->featureEnabled(AuthFeature::Rbac)) {
            if ($roles !== [] || $permissions !== []) {
                throw AuthException::invalidConfiguration('Membership access assignments require the RBAC feature.');
            }

            return;
        }
        if (! $principal instanceof Model || ! method_exists($principal, 'syncRoles') || ! method_exists($principal, 'syncPermissions')) {
            throw AuthException::invalidConfiguration('The membership principal must support tenant RBAC assignments.');
        }
        [$roleRecords, $permissionRecords] = $this->records($roles, $permissions);
        setPermissionsTeamId($this->ownership->requireOwner()->scopeKey());
        $principal->syncRoles($roleRecords);
        $principal->syncPermissions($permissionRecords);
        $this->container->make(RbacPrincipalTracker::class)->clearRelations();
    }

    /**
     * Resolve invitation inputs to immutable role and permission identifiers.
     *
     * @param  list<string>  $roles
     * @param  list<string>  $permissions
     * @return array{roles: list<string>, permissions: list<string>}
     */
    public function canonicalIdentifiers(array $roles, array $permissions): array
    {
        if (! $this->configuration->featureEnabled(AuthFeature::Rbac)) {
            if ($roles !== [] || $permissions !== []) {
                throw AuthException::invalidConfiguration('Membership access assignments require the RBAC feature.');
            }

            return ['roles' => [], 'permissions' => []];
        }
        [$roleRecords, $permissionRecords] = $this->records($roles, $permissions);

        return [
            'roles' => array_values($roleRecords->map(static fn (Role $role): string => $role->id)->all()),
            'permissions' => array_values($permissionRecords->map(static fn (Permission $permission): string => $permission->id)->all()),
        ];
    }

    /**
     * @param  list<string>  $roles
     * @param  list<string>  $permissions
     * @return array{0: Collection<int, Role>, 1: Collection<int, Permission>}
     */
    private function records(array $roles, array $permissions): array
    {
        $roleClass = $this->models->roleClass();
        $permissionClass = $this->models->permissionClass();
        $guard = $this->configuration->string('features.rbac.settings.guard', 'web');
        // A name is never compared with the UUID key: PostgreSQL rejects a non-UUID value there instead of matching nothing.
        $roleIds = array_values(array_filter($roles, Str::isUuid(...)));
        $permissionIds = array_values(array_filter($permissions, Str::isUuid(...)));
        $roleRecords = $this->boundary->query($roleClass::query(), 'auth.roles')->where('guard_name', $guard)
            ->where(static fn ($query) => $query->whereIn('id', $roleIds)->orWhereIn('name', $roles))->get();
        $permissionRecords = $permissionClass::query()->where('guard_name', $guard)
            ->where(static fn ($query) => $query->whereIn('id', $permissionIds)->orWhereIn('name', $permissions))->get();
        if ($roleRecords->count() !== count($roles) || $permissionRecords->count() !== count($permissions)) {
            throw new AuthException('membership_assignment_invalid', 'A membership access assignment is invalid.', 422);
        }

        return [$roleRecords, $permissionRecords];
    }
}
