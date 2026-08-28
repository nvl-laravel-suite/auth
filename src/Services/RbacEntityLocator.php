<?php

declare(strict_types=1);

namespace Nvl\Auth\Services;

use Illuminate\Database\Eloquent\ModelNotFoundException;
use Illuminate\Support\Collection;
use Illuminate\Support\Str;
use Nvl\Auth\Exceptions\AuthException;
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
    public function __construct(
        private AuthModelRegistry $models,
        private ?AuthConfiguration $configuration = null,
        private ?RbacConsumerLimits $limits = null,
    ) {}

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

    /** Resolve one canonical role through the configured model and guard. */
    public function roleForConfiguredGuard(Role|string $role): Role
    {
        $class = $this->models->roleClass();

        if ($role instanceof Role && ! $role instanceof $class) {
            throw (new ModelNotFoundException)->setModel($class, [$role->id]);
        }

        $identifier = $role instanceof Role ? $role->id : $role;
        $guard = $this->configuration()->string('features.rbac.settings.guard', 'web');

        return $class::query()
            ->where('guard_name', $guard)
            ->findOrFail($identifier);
    }

    /**
     * Resolve one role by guard and canonical name.
     */
    public function roleByName(string $name, string $guard): Role
    {
        $class = $this->models->roleClass();

        return $class::query()
            ->where('name', $name)
            ->where('guard_name', $guard)
            ->firstOrFail();
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

    /**
     * Resolve mixed role IDs and names for the configured guard in caller order.
     *
     * @param  array<int, mixed>  $identifiers
     * @return Collection<int, Role>
     */
    public function rolesByIdentifiers(array $identifiers): Collection
    {
        $identifiers = $this->normalizeIdentifiers($identifiers, 'role');
        $class = $this->models->roleClass();

        if ($identifiers === []) {
            return (new $class)->newCollection();
        }

        $guard = $this->configuration()->string('features.rbac.settings.guard', 'web');
        $uuidIdentifiers = array_values(array_filter(
            $identifiers,
            static fn (string $identifier): bool => Str::isUuid($identifier),
        ));
        $byId = [];

        if ($uuidIdentifiers !== []) {
            $idMatches = $class::query()
                ->select(['id', 'name', 'guard_name', 'display_name', 'description', 'is_system'])
                ->where('guard_name', $guard)
                ->whereIn('id', $uuidIdentifiers)
                ->get();

            foreach ($idMatches as $role) {
                $byId[$role->id] = $role;
            }
        }

        $nameMatches = $class::query()
            ->select(['id', 'name', 'guard_name', 'display_name', 'description', 'is_system'])
            ->where('guard_name', $guard)
            ->whereIn('name', $identifiers)
            ->get();
        $byName = [];

        foreach ($nameMatches as $role) {
            $byName[$role->name][] = $role;
        }

        $resolved = [];
        $resolvedIds = [];

        foreach ($identifiers as $identifier) {
            $matches = $byName[$identifier] ?? [];

            if (Str::isUuid($identifier) && isset($byId[$identifier])) {
                array_unshift($matches, $byId[$identifier]);
            }

            $matches = $this->uniqueRoles($matches);

            if ($matches === []) {
                throw new AuthException(
                    'role_identifier_not_found',
                    'The requested role identifier was not found for the configured guard.',
                    422,
                    ['identifier' => $identifier],
                );
            }

            if (count($matches) > 1) {
                throw new AuthException(
                    'ambiguous_role_identifier',
                    'The requested role identifier is ambiguous.',
                    422,
                    ['identifier' => $identifier],
                );
            }

            $role = $matches[0];

            if (isset($resolvedIds[$role->id])) {
                throw new AuthException(
                    'duplicate_role_identifier',
                    'Multiple identifiers resolve to the same role.',
                    422,
                    ['identifier' => $identifier],
                );
            }

            $resolvedIds[$role->id] = true;
            $resolved[] = $role;
        }

        return collect($resolved);
    }

    /**
     * Resolve mixed permission IDs and names for the configured guard in caller order.
     *
     * @param  array<int, mixed>  $identifiers
     * @return Collection<int, Permission>
     */
    public function permissionsByIdentifiers(array $identifiers): Collection
    {
        $identifiers = $this->normalizeIdentifiers($identifiers, 'permission');
        $class = $this->models->permissionClass();

        if ($identifiers === []) {
            return (new $class)->newCollection();
        }

        $guard = $this->configuration()->string('features.rbac.settings.guard', 'web');
        $uuidIdentifiers = array_values(array_filter(
            $identifiers,
            static fn (string $identifier): bool => Str::isUuid($identifier),
        ));
        $byId = [];

        if ($uuidIdentifiers !== []) {
            $idMatches = $class::query()
                ->select(['id', 'name', 'guard_name', 'display_name', 'description', 'group'])
                ->where('guard_name', $guard)
                ->whereIn('id', $uuidIdentifiers)
                ->get();

            foreach ($idMatches as $permission) {
                $byId[$permission->id] = $permission;
            }
        }

        $nameMatches = $class::query()
            ->select(['id', 'name', 'guard_name', 'display_name', 'description', 'group'])
            ->where('guard_name', $guard)
            ->whereIn('name', $identifiers)
            ->get();
        $byName = [];

        foreach ($nameMatches as $permission) {
            $byName[$permission->name][] = $permission;
        }

        $resolved = [];
        $resolvedIds = [];

        foreach ($identifiers as $identifier) {
            $matches = $byName[$identifier] ?? [];

            if (Str::isUuid($identifier) && isset($byId[$identifier])) {
                array_unshift($matches, $byId[$identifier]);
            }

            $matches = $this->uniquePermissions($matches);

            if ($matches === []) {
                throw new AuthException(
                    'permission_identifier_not_found',
                    'The requested permission identifier was not found for the configured guard.',
                    422,
                    ['identifier' => $identifier],
                );
            }

            if (count($matches) > 1) {
                throw new AuthException(
                    'ambiguous_permission_identifier',
                    'The requested permission identifier is ambiguous.',
                    422,
                    ['identifier' => $identifier],
                );
            }

            $permission = $matches[0];

            if (isset($resolvedIds[$permission->id])) {
                throw new AuthException(
                    'duplicate_permission_identifier',
                    'Multiple identifiers resolve to the same permission.',
                    422,
                    ['identifier' => $identifier],
                );
            }

            $resolvedIds[$permission->id] = true;
            $resolved[] = $permission;
        }

        return collect($resolved);
    }

    /**
     * Remove duplicate query matches by role ID.
     *
     * @param  list<Role>  $roles
     * @return list<Role>
     */
    private function uniqueRoles(array $roles): array
    {
        $unique = [];

        foreach ($roles as $role) {
            $unique[$role->id] = $role;
        }

        return array_values($unique);
    }

    /**
     * Remove duplicate query matches by permission ID.
     *
     * @param  list<Permission>  $permissions
     * @return list<Permission>
     */
    private function uniquePermissions(array $permissions): array
    {
        $unique = [];

        foreach ($permissions as $permission) {
            $unique[$permission->id] = $permission;
        }

        return array_values($unique);
    }

    /**
     * Normalize and validate untrusted identifier lists before querying storage.
     *
     * @param  array<int, mixed>  $identifiers
     * @return list<string>
     */
    private function normalizeIdentifiers(array $identifiers, string $entity): array
    {
        $limit = $this->limits()->identifierResolutionLimit();

        if (count($identifiers) > $limit) {
            throw new AuthException(
                "too_many_{$entity}_identifiers",
                ucfirst($entity)." identifier lists may contain at most {$limit} values.",
            );
        }

        $normalized = [];
        $seen = [];

        foreach ($identifiers as $identifier) {
            if (! is_string($identifier)) {
                throw new AuthException(
                    "invalid_{$entity}_identifier",
                    ucfirst($entity).' identifiers must be strings.',
                );
            }

            $identifier = trim($identifier);

            if ($identifier === '') {
                throw new AuthException(
                    "invalid_{$entity}_identifier",
                    ucfirst($entity).' identifiers may not be empty.',
                );
            }

            if (mb_strlen($identifier) > 160) {
                throw new AuthException(
                    "invalid_{$entity}_identifier",
                    ucfirst($entity).' identifiers may not exceed 160 characters.',
                );
            }

            if (isset($seen[$identifier])) {
                throw new AuthException(
                    "duplicate_{$entity}_identifier",
                    ucfirst($entity).' identifier lists may not contain duplicate values.',
                );
            }

            $seen[$identifier] = true;
            $normalized[] = $identifier;
        }

        return $normalized;
    }

    /** Resolve the optional configuration collaborator for legacy construction. */
    private function configuration(): AuthConfiguration
    {
        return $this->configuration ?? app(AuthConfiguration::class);
    }

    /** Resolve the optional consumer limit collaborator for legacy construction. */
    private function limits(): RbacConsumerLimits
    {
        return $this->limits ?? app(RbacConsumerLimits::class);
    }
}
