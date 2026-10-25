<?php

declare(strict_types=1);

namespace Nvl\Auth\Services;

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Contracts\Pagination\LengthAwarePaginator;
use Illuminate\Database\Eloquent\Builder;
use Illuminate\Database\Query\Builder as QueryBuilder;
use Illuminate\Support\Collection;
use Illuminate\Support\Facades\Validator;
use Illuminate\Support\Str;
use InvalidArgumentException;
use LogicException;
use Nvl\Auth\Contracts\PrincipalAttributeMapper;
use Nvl\Auth\Enums\AuthFeature;
use Nvl\Auth\Enums\FeatureOperation;
use Nvl\Auth\Enums\PrincipalAttribute;
use Nvl\Auth\Exceptions\AuthException;
use Nvl\Auth\Models\Permission;
use Nvl\Auth\Models\Role;
use stdClass;

/** Complete native AuthRbacReader operations.
 * @api
 */
final readonly class AuthRbacReader
{
    /** Native Auth operation. */
    public function __construct(private FeatureGate $features, private ManagementAuthorizer $authorization, private AuthModelRegistry $models, private AuthConfiguration $configuration, private RbacPermissionGroupExpressions $groupExpressions, private RbacConsumerLimits $limits, private RbacOptionReadService $options, private RoleHierarchy $hierarchy, private RoleTemplateRegistry $templates, private RbacEntityLocator $entities, private PrincipalAttributeMapper $principalAttributes) {}

    /** Return availability within the configured RBAC guard.
     * @return array<string, mixed>
     */
    public function roleNameAvailability(Authenticatable $actor, string $name, ?string $exceptId = null): array
    {
        $this->features->assertAllowed(AuthFeature::Rbac, FeatureOperation::Read);
        $this->authorization->authorize($actor, 'nvl.auth.rbac.view');
        $name = trim($name);
        if ($name === '' || mb_strlen($name) > 160) {
            throw new AuthException('invalid_role_name', 'Role names must contain between one and 160 characters.');
        }
        if ($exceptId !== null) {
            $exceptId = trim($exceptId);
            if (! Str::isUuid($exceptId)) {
                throw new AuthException('invalid_role_identifier', 'Excluded role identifiers must be UUIDs.');
            }
        }
        $class = $this->models->roleClass();
        $guard = $this->configuration->string('features.rbac.settings.guard', 'web');
        $conflictingRoleId = $class::query()->where('guard_name', $guard)->where('name', $name)->when($exceptId !== null, static fn ($query) => $query->whereKeyNot($exceptId))->value('id');
        $conflictingRoleId = is_string($conflictingRoleId) ? $conflictingRoleId : null;

        return ['name' => $name, 'available' => $conflictingRoleId === null, 'conflictingRoleId' => $conflictingRoleId];
    }

    /**
     * Return a bounded paginator whose items are package DTOs, never models.
     *
     * @param  array<string, mixed>  $data
     * @return LengthAwarePaginator<int, Permission>
     */
    public function permissionCatalog(Authenticatable $actor, array $data): LengthAwarePaginator
    {
        $this->features->assertAllowed(AuthFeature::Rbac, FeatureOperation::Read);
        $data = $this->validatePermissionIndexQuery($data);
        $this->authorization->authorize($actor, 'nvl.auth.rbac.view');
        $this->permissionCatalogAssertMaximumLength($data['search'], 160, 'Permission search');
        $this->permissionCatalogAssertMaximumLength($data['group'], 120, 'Permission group');
        $this->permissionCatalogAssertMaximumLength($data['guard'], 120, 'Permission guard');
        $class = $this->models->permissionClass();
        $query = $class::query()->select(['id', 'name', 'display_name', 'description', 'guard_name', 'group', 'created_at'])->withCount(['roles', 'users']);
        if ($data['includeAssignments']) {
            $query->with('roles:id');
        }
        $search = trim((string) $data['search']);
        if ($search !== '') {
            $term = "%{$search}%";
            $query->where(static function ($searchQuery) use ($term): void {
                $searchQuery->where('name', 'like', $term)->orWhere('display_name', 'like', $term)->orWhere('description', 'like', $term)->orWhere('group', 'like', $term);
            });
        }
        $group = RbacPermissionGroupExpressions::normalize($data['group']);
        if ($group !== null) {
            $this->permissionCatalogApplyGroupFilter($query, $group);
        }
        $guard = trim((string) $data['guard']);
        if ($guard !== '') {
            $query->where('guard_name', $guard);
        }
        $this->permissionCatalogApplyOrdering($query, $data);
        $paginator = $query->paginate(max(1, min($data['perPage'] ?? 25, 100)));

        return $paginator;
    }

    /**
     * Apply an exact filter using the same general-group normalization as DTOs.
     *
     * @param  Builder<Permission>  $query
     */
    private function permissionCatalogApplyGroupFilter(Builder $query, string $group): void
    {
        $query->where($this->groupExpressions->normalized($query), $group);
    }

    /**
     * Apply an allowlisted, database-portable permission ordering.
     *
     * @param  Builder<Permission>  $query
     * @param  array<string, mixed>  $data
     */
    private function permissionCatalogApplyOrdering(Builder $query, array $data): void
    {
        $data = $this->validatePermissionIndexQuery($data);
        $direction = $data['direction'] === 'desc' ? 'desc' : 'asc';
        if ($data['sort'] === null || $data['sort'] === 'group') {
            $query->orderBy($this->groupExpressions->normalized($query), $direction);
        } elseif ($data['sort'] === 'label') {
            $query->orderByRaw($direction === 'desc' ? "COALESCE(NULLIF(TRIM(display_name), ''), name) DESC" : "COALESCE(NULLIF(TRIM(display_name), ''), name) ASC");
        } else {
            $query->orderBy($data['sort'], $direction);
        }
        if ($data['sort'] === null) {
            $query->orderBy('name');
        }
        $query->orderBy('id');
    }

    /** Reject oversized direct PHP input before it reaches a query. */
    private function permissionCatalogAssertMaximumLength(?string $value, int $maximum, string $label): void
    {
        if ($value !== null && mb_strlen(trim($value)) > $maximum) {
            throw new AuthException('invalid_permission_catalog_query', "{$label} may not exceed {$maximum} characters.");
        }
    }

    /**
     * Aggregate raw database groups in one query and normalize them in memory.
     *
     * @return Collection<int, array{value: string, label: string, permissionsCount: int}>
     */
    public function permissionGroups(Authenticatable $actor): Collection
    {
        $this->features->assertAllowed(AuthFeature::Rbac, FeatureOperation::Read);
        $this->authorization->authorize($actor, 'nvl.auth.rbac.view');
        $class = $this->models->permissionClass();
        $query = $class::query();
        $rows = $query->select($this->groupExpressions->selected($query))->selectRaw('COUNT(*) AS permissions_count')->groupBy('normalized_group')->orderBy('normalized_group')->limit($this->limits->permissionGroupLimit())->get();

        return $rows->map(static function ($row): array {
            $group = $row->getAttribute('normalized_group');
            $count = $row->getAttribute('permissions_count');
            if (! is_string($group) || ! is_numeric($count)) {
                throw new LogicException('Permission group aggregates returned an invalid database value.');
            }

            return ['value' => $group, 'label' => Str::headline($group), 'permissionsCount' => (int) $count];
        })->values();
    }

    /**
     * Return minimal permission projections without exposing Eloquent models.
     *
     * @return Collection<int, Permission>
     */
    public function permissionOptions(Authenticatable $actor, ?string $search = null, ?string $group = null, ?int $limit = null): Collection
    {
        $this->features->assertAllowed(AuthFeature::Rbac, FeatureOperation::Read);
        $this->authorization->authorize($actor, 'nvl.auth.rbac.view');
        $search = $this->permissionOptionsNormalizedSearch($search);
        $group = $this->permissionOptionsNormalizedGroup($group);

        return $this->options->permissions($search, $group, $this->limits->permissionOptionLimit($limit));
    }

    /** Normalize and constrain an untrusted selector search. */
    private function permissionOptionsNormalizedSearch(?string $search): ?string
    {
        $search = trim((string) $search);
        if (mb_strlen($search) > 160) {
            throw new AuthException('invalid_permission_search', 'Permission search may not exceed 160 characters.');
        }

        return $search !== '' ? $search : null;
    }

    /** Normalize and constrain an exact permission group filter. */
    private function permissionOptionsNormalizedGroup(?string $group): ?string
    {
        $rawGroup = (string) $group;
        if (mb_strlen($rawGroup) > 120) {
            throw new AuthException('invalid_permission_group', 'Permission group may not exceed 120 characters.');
        }

        return RbacPermissionGroupExpressions::normalize($rawGroup);
    }

    /** @return LengthAwarePaginator<int, Permission> */
    public function permissions(Authenticatable $actor, ?string $search = null, ?string $group = null, int $perPage = 25): LengthAwarePaginator
    {
        $this->features->assertAllowed(AuthFeature::Rbac, FeatureOperation::Read);
        $this->authorization->authorize($actor, 'nvl.auth.rbac.view');
        $class = $this->models->permissionClass();
        $query = $class::query()->withCount(['roles', 'users']);
        if ($search !== null && trim($search) !== '') {
            $term = '%'.trim($search).'%';
            $query->where(static function ($searchQuery) use ($term): void {
                $searchQuery->where('name', 'like', $term)->orWhere('display_name', 'like', $term);
            });
        }
        if ($group !== null && trim($group) !== '') {
            $query->where('group', trim($group));
        }
        $permissions = $query->orderBy('group')->orderBy('name')->paginate(max(1, min($perPage, 100)));

        return $permissions;
    }

    /**
     * Return a bounded paginator whose items are package DTOs, never models.
     *
     * @param  array<string, mixed>  $data
     * @return LengthAwarePaginator<int, Role>
     */
    public function roleCatalog(Authenticatable $actor, array $data): LengthAwarePaginator
    {
        $this->features->assertAllowed(AuthFeature::Rbac, FeatureOperation::Read);
        $data = $this->validateRoleIndexQuery($data);
        $this->authorization->authorize($actor, 'nvl.auth.rbac.view');
        $this->roleCatalogAssertMaximumLength($data['search'], 160, 'Role search');
        $this->roleCatalogAssertMaximumLength($data['guard'], 120, 'Role guard');
        $class = $this->models->roleClass();
        $query = $class::query()->select(['id', 'name', 'display_name', 'description', 'guard_name', 'is_system', 'priority', 'parent_id', 'created_at'])->with('parent:id,name')->withCount(['permissions', 'users']);
        if ($data['includeAssignments']) {
            $query->with('permissions:id');
        }
        $search = trim((string) $data['search']);
        if ($search !== '') {
            $term = "%{$search}%";
            $query->where(static function ($searchQuery) use ($term): void {
                $searchQuery->where('name', 'like', $term)->orWhere('display_name', 'like', $term)->orWhere('description', 'like', $term);
            });
        }
        if ($data['isSystem'] !== null) {
            $query->where('is_system', $data['isSystem']);
        }
        $guard = trim((string) $data['guard']);
        if ($guard !== '') {
            $query->where('guard_name', $guard);
        }
        $this->roleCatalogApplyOrdering($query, $data);
        $paginator = $query->paginate(max(1, min($data['perPage'] ?? 25, 100)));

        return $paginator;
    }

    /**
     * Apply an allowlisted, database-portable role ordering.
     *
     * @param  Builder<Role>  $query
     * @param  array<string, mixed>  $data
     */
    private function roleCatalogApplyOrdering(Builder $query, array $data): void
    {
        $data = $this->validateRoleIndexQuery($data);
        $direction = $data['direction'] === 'desc' ? 'desc' : 'asc';
        if ($data['sort'] === null) {
            $query->orderByDesc('priority')->orderBy('name')->orderBy('id');

            return;
        }
        if ($data['sort'] === 'label') {
            $query->orderByRaw($direction === 'desc' ? "COALESCE(NULLIF(TRIM(display_name), ''), name) DESC" : "COALESCE(NULLIF(TRIM(display_name), ''), name) ASC");
        } else {
            $query->orderBy($data['sort'], $direction);
        }
        $query->orderBy('id');
    }

    /** Reject oversized direct PHP input before it reaches a query. */
    private function roleCatalogAssertMaximumLength(?string $value, int $maximum, string $label): void
    {
        if ($value !== null && mb_strlen(trim($value)) > $maximum) {
            throw new AuthException('invalid_role_catalog_query', "{$label} may not exceed {$maximum} characters.");
        }
    }

    /** @return list<array{id: string, name: string, display_name: string|null, priority: int, user_count: int, children: list<mixed>}> */
    public function roleHierarchy(Authenticatable $actor): array
    {
        $this->features->assertAllowed(AuthFeature::Rbac, FeatureOperation::Read);
        $this->authorization->authorize($actor, 'nvl.auth.rbac.view');
        $class = $this->models->roleClass();
        $roles = $class::query()->withCount('users')->orderByDesc('priority')->orderBy('name')->get();

        return $this->hierarchy->tree($roles);
    }

    /**
     * Return minimal role projections without exposing Eloquent models.
     *
     * @return Collection<int, Role>
     */
    public function roleOptions(Authenticatable $actor, ?string $search = null, ?int $limit = null): Collection
    {
        $this->features->assertAllowed(AuthFeature::Rbac, FeatureOperation::Read);
        $this->authorization->authorize($actor, 'nvl.auth.rbac.view');
        $search = $this->roleOptionsNormalizedSearch($search);

        return $this->options->roles($search, $this->limits->roleOptionLimit($limit));
    }

    /** Normalize and constrain an untrusted selector search. */
    private function roleOptionsNormalizedSearch(?string $search): ?string
    {
        $search = trim((string) $search);
        if (mb_strlen($search) > 160) {
            throw new AuthException('invalid_role_search', 'Role search may not exceed 160 characters.');
        }

        return $search !== '' ? $search : null;
    }

    /**
     * Return every validated template with presentation and hierarchy metadata.
     *
     * @return list<array<string, mixed>>
     */
    public function roleTemplates(Authenticatable $actor): array
    {
        $this->features->assertAllowed(AuthFeature::Rbac, FeatureOperation::Read);
        $this->authorization->authorize($actor, 'nvl.auth.rbac.view');

        return array_values(array_map(static fn ($template): array => $template->toArray(), $this->templates->roles()));
    }

    /** @return LengthAwarePaginator<int, Role> */
    public function roles(Authenticatable $actor, ?string $search = null, int $perPage = 25): LengthAwarePaginator
    {
        $this->features->assertAllowed(AuthFeature::Rbac, FeatureOperation::Read);
        $this->authorization->authorize($actor, 'nvl.auth.rbac.view');
        $class = $this->models->roleClass();
        $query = $class::query()->with('parent')->withCount(['users', 'permissions']);
        if ($search !== null && trim($search) !== '') {
            $term = '%'.trim($search).'%';
            $query->where(static function ($searchQuery) use ($term): void {
                $searchQuery->where('name', 'like', $term)->orWhere('display_name', 'like', $term);
            });
        }
        $roles = $query->orderByDesc('priority')->orderBy('name')->paginate(max(1, min($perPage, 100)));

        return $roles;
    }

    /**
     * Resolve permission identifiers in caller order without exposing models.
     *
     * @param  list<string>  $identifiers
     * @return Collection<int, Permission>
     */
    public function resolvePermissions(Authenticatable $actor, array $identifiers): Collection
    {
        $this->features->assertAllowed(AuthFeature::Rbac, FeatureOperation::Read);
        $this->authorization->authorize($actor, 'nvl.auth.rbac.view');

        return $this->entities->permissionsByIdentifiers($identifiers);
    }

    /**
     * Resolve role identifiers in caller order without exposing models.
     *
     * @param  list<string>  $identifiers
     * @return Collection<int, Role>
     */
    public function resolveRoles(Authenticatable $actor, array $identifiers): Collection
    {
        $this->features->assertAllowed(AuthFeature::Rbac, FeatureOperation::Read);
        $this->authorization->authorize($actor, 'nvl.auth.rbac.view');

        return $this->entities->rolesByIdentifiers($identifiers);
    }

    /** Return one permission. */
    public function permission(Authenticatable $actor, Permission|string $permission): Permission
    {
        $this->features->assertAllowed(AuthFeature::Rbac, FeatureOperation::Read);
        $this->authorization->authorize($actor, 'nvl.auth.rbac.view');
        $permission = $this->entities->permission($permission);

        return $permission->load('roles')->loadCount('users');

    }

    /** Return current package RBAC aggregates.
     * @return array<string, mixed>
     */
    public function analytics(Authenticatable $actor): array
    {
        $this->features->assertAllowed(AuthFeature::Rbac, FeatureOperation::Read);
        $this->authorization->authorize($actor, 'nvl.auth.rbac.view');
        $roleClass = $this->models->roleClass();
        $permissionClass = $this->models->permissionClass();
        $roles = $roleClass::query()->withCount(['users', 'permissions'])->get();
        $permissions = $permissionClass::query()->withCount('users')->get();
        $largest = array_values($roles->sortByDesc('users_count')->take(10)->values()->map(static fn (Role $role): array => ['id' => $role->id, 'name' => $role->name, 'users_count' => $role->users_count ?? 0, 'permissions_count' => $role->permissions_count ?? 0])->all());
        $roleAssignments = $roles->reduce(static fn (int $total, Role $role): int => $total + ($role->users_count ?? 0), 0);
        $directAssignments = $permissions->reduce(static fn (int $total, Permission $permission): int => $total + ($permission->users_count ?? 0), 0);

        return ['roles' => $roles->count(), 'permissions' => $permissions->count(), 'roleAssignments' => $roleAssignments, 'directPermissionAssignments' => $directAssignments, 'unassignedRoles' => $roles->where('users_count', 0)->count(), 'largestRoles' => $largest];
    }

    /** Return one role. */
    public function role(Authenticatable $actor, Role|string $role): Role
    {
        $this->features->assertAllowed(AuthFeature::Rbac, FeatureOperation::Read);
        $this->authorization->authorize($actor, 'nvl.auth.rbac.view');

        return $this->entities->role($role)->load(['parent', 'children', 'permissions'])->loadCount('users');
    }

    /** Calculate current aggregates without loading related identities.
     * @return array<string, mixed>
     */
    public function roleAnalytics(Authenticatable $actor, Role|string $role): array
    {
        $this->features->assertAllowed(AuthFeature::Rbac, FeatureOperation::Read);
        $this->authorization->authorize($actor, 'nvl.auth.rbac.view');
        $role = $this->entities->roleForConfiguredGuard($role);
        [$users, $activeUsers] = $this->roleAnalyticsUserCounts($role);
        [$permissions, $permissionGroups] = $this->roleAnalyticsPermissionCounts($role);
        $hierarchy = $this->roleAnalyticsHierarchy($role);

        return ['roleId' => $role->id, 'users' => $users, 'activeUsers' => $activeUsers, 'inactiveUsers' => max(0, $users - $activeUsers), 'permissions' => $permissions, 'children' => $hierarchy['children'], 'descendants' => $hierarchy['descendants'], 'parentName' => $hierarchy['parentName'], 'permissionGroups' => $permissionGroups];
    }

    /**
     * Count all and active assigned principals in one aggregate query.
     *
     * @return array{int, int}
     */
    private function roleAnalyticsUserCounts(Role $role): array
    {
        $class = $this->models->rbacPrincipalClass();
        $query = $class::query()->whereHas('roles', static function (Builder $roles) use ($role): void {
            $roles->whereKey($role->id);
        });
        $activeColumn = $query->getModel()->qualifyColumn($this->principalAttributes->column(PrincipalAttribute::Active));
        $allUsers = (clone $query)->selectRaw('COUNT(*)');
        $activeUsers = (clone $query)->where($activeColumn, true)->selectRaw('COUNT(*)');
        $row = (new QueryBuilder($query->getQuery()->getConnection()))->selectSub($allUsers->toBase(), 'aggregate_users')->selectSub($activeUsers->toBase(), 'aggregate_active_users')->first();
        if (! $row instanceof stdClass) {
            return [0, 0];
        }

        return [$this->roleAnalyticsInteger($row->aggregate_users ?? null), $this->roleAnalyticsInteger($row->aggregate_active_users ?? null)];
    }

    /**
     * Count direct permissions and their canonical groups in one query.
     *
     * @return array{int, array<string, int>}
     */
    private function roleAnalyticsPermissionCounts(Role $role): array
    {
        $class = $this->models->permissionClass();
        $query = $class::query()->whereHas('roles', static function (Builder $roles) use ($role): void {
            $roles->whereKey($role->id);
        });
        $rows = $query->select([$this->groupExpressions->selected($query)])->selectRaw('COUNT(*) AS permissions_count')->groupBy('normalized_group')->toBase()->get();
        $groups = [];
        foreach ($rows as $row) {
            if (! is_string($row->normalized_group ?? null)) {
                continue;
            }
            $groups[$row->normalized_group] = $this->roleAnalyticsInteger($row->permissions_count ?? null);
        }

        return [array_sum($groups), $groups];
    }

    /**
     * Read the configured-guard graph once and traverse it with a visited set.
     *
     * @return array{children: int, descendants: int, parentName: string|null}
     */
    private function roleAnalyticsHierarchy(Role $role): array
    {
        $class = $this->models->roleClass();
        $roles = $class::query()->select(['id', 'parent_id', 'name'])->where('guard_name', $role->guard_name)->get();
        $nodes = [];
        $childrenByParent = [];
        foreach ($roles as $candidate) {
            $nodes[$candidate->id] = ['name' => $candidate->name, 'parentId' => $candidate->parent_id];
            if ($candidate->parent_id !== null) {
                $childrenByParent[$candidate->parent_id][] = $candidate->id;
            }
        }
        $directChildren = array_values(array_unique(array_filter($childrenByParent[$role->id] ?? [], static fn (string $identifier): bool => $identifier !== $role->id)));
        $queue = $directChildren;
        $visited = [$role->id => true];
        $descendants = 0;
        for ($offset = 0; isset($queue[$offset]); $offset++) {
            $identifier = $queue[$offset];
            if (isset($visited[$identifier])) {
                continue;
            }
            $visited[$identifier] = true;
            $descendants++;
            foreach ($childrenByParent[$identifier] ?? [] as $childIdentifier) {
                $queue[] = $childIdentifier;
            }
        }
        $parentId = $nodes[$role->id]['parentId'] ?? null;
        $parentName = is_string($parentId) && isset($nodes[$parentId]) ? $nodes[$parentId]['name'] : null;

        return ['children' => count($directChildren), 'descendants' => $descendants, 'parentName' => $parentName];
    }

    /** Normalize a database aggregate scalar without coercing objects or arrays. */
    private function roleAnalyticsInteger(mixed $value): int
    {
        return is_numeric($value) ? (int) $value : 0;
    }

    /**
     * Return defaults for an empty search and no results for a one-character search.
     *
     * @return Collection<int, Permission>
     */
    public function suggestPermissions(Authenticatable $actor, ?string $search = null, ?string $group = null, ?int $limit = null): Collection
    {
        $this->features->assertAllowed(AuthFeature::Rbac, FeatureOperation::Read);
        $this->authorization->authorize($actor, 'nvl.auth.rbac.view');
        $search = trim((string) $search);
        $group = $this->suggestPermissionsNormalizedGroup($group);
        if (mb_strlen($search) > 160) {
            throw new AuthException('invalid_permission_search', 'Permission search may not exceed 160 characters.');
        }
        if ($search === '') {
            return $this->options->permissions(null, $group, $this->limits->permissionOptionLimit($limit));
        }
        if (mb_strlen($search) === 1) {
            return new Collection;
        }

        return $this->options->permissions($search, $group, $this->limits->permissionOptionLimit($limit));
    }

    /** Normalize and constrain an exact permission group filter. */
    private function suggestPermissionsNormalizedGroup(?string $group): ?string
    {
        $rawGroup = (string) $group;
        if (mb_strlen($rawGroup) > 120) {
            throw new AuthException('invalid_permission_group', 'Permission group may not exceed 120 characters.');
        }

        return RbacPermissionGroupExpressions::normalize($rawGroup);
    }

    /**
     * Return defaults for an empty search and no results for a one-character search.
     *
     * @return Collection<int, Role>
     */
    public function suggestRoles(Authenticatable $actor, ?string $search = null, ?int $limit = null): Collection
    {
        $this->features->assertAllowed(AuthFeature::Rbac, FeatureOperation::Read);
        $this->authorization->authorize($actor, 'nvl.auth.rbac.view');
        $search = trim((string) $search);
        if (mb_strlen($search) > 160) {
            throw new AuthException('invalid_role_search', 'Role search may not exceed 160 characters.');
        }
        if ($search === '') {
            return $this->options->roles(null, $this->limits->roleOptionLimit($limit));
        }
        if (mb_strlen($search) === 1) {
            return new Collection;
        }

        return $this->options->roles($search, $this->limits->roleOptionLimit($limit));
    }

    /**
     * @param  array<string, mixed>  $data
     * @return array{search: string|null, group: string|null, perPage: int|null, guard: string|null, sort: string|null, direction: string|null, includeAssignments: bool}
     */
    private function validatePermissionIndexQuery(array $data): array
    {
        if (array_diff(array_keys($data), ['search', 'group', 'perPage', 'guard', 'sort', 'direction', 'includeAssignments']) !== []) {
            throw new InvalidArgumentException('Unknown or protected Auth input fields.');
        }
        if (! array_key_exists('search', $data)) {
            $data['search'] = null;
        }
        if (! ($data['search'] === null || is_string($data['search']))) {
            throw new InvalidArgumentException('Invalid Auth input [search].');
        }
        if (! array_key_exists('group', $data)) {
            $data['group'] = null;
        }
        if (! ($data['group'] === null || is_string($data['group']))) {
            throw new InvalidArgumentException('Invalid Auth input [group].');
        }
        if (! array_key_exists('perPage', $data)) {
            $data['perPage'] = null;
        }
        if (! ($data['perPage'] === null || is_int($data['perPage']))) {
            throw new InvalidArgumentException('Invalid Auth input [perPage].');
        }
        if (! array_key_exists('guard', $data)) {
            $data['guard'] = null;
        }
        if (! ($data['guard'] === null || is_string($data['guard']))) {
            throw new InvalidArgumentException('Invalid Auth input [guard].');
        }
        if (! array_key_exists('sort', $data)) {
            $data['sort'] = null;
        }
        if (! ($data['sort'] === null || is_string($data['sort']))) {
            throw new InvalidArgumentException('Invalid Auth input [sort].');
        }
        if (! array_key_exists('direction', $data)) {
            $data['direction'] = null;
        }
        if (! ($data['direction'] === null || is_string($data['direction']))) {
            throw new InvalidArgumentException('Invalid Auth input [direction].');
        }
        if (! array_key_exists('includeAssignments', $data)) {
            $data['includeAssignments'] = false;
        }
        if (! is_bool($data['includeAssignments'] ?? null)) {
            throw new InvalidArgumentException('Invalid Auth input [includeAssignments].');
        }
        Validator::make($data, ['search' => ['nullable', 'sometimes', 'string', 'max:160'], 'group' => ['nullable', 'sometimes', 'string', 'max:120'], 'perPage' => ['nullable', 'sometimes', 'integer'], 'guard' => ['nullable', 'sometimes', 'string', 'max:120'], 'sort' => ['nullable', 'sometimes', 'string', 'in:name,label,group,created_at'], 'direction' => ['nullable', 'sometimes', 'string', 'in:asc,desc'], 'includeAssignments' => ['sometimes', 'boolean']])->validate();
        if ($data['sort'] !== null && ! in_array($data['sort'], ['name', 'label', 'group', 'created_at'], true)) {
            throw new InvalidArgumentException('The permission catalog sort is not supported.');
        }
        if ($data['direction'] !== null && ! in_array($data['direction'], ['asc', 'desc'], true)) {
            throw new InvalidArgumentException('The permission catalog direction is not supported.');
        }

        return $data;
    }

    /**
     * @param  array<string, mixed>  $data
     * @return array{search: string|null, perPage: int|null, isSystem: bool|null, guard: string|null, sort: string|null, direction: string|null, includeAssignments: bool}
     */
    private function validateRoleIndexQuery(array $data): array
    {
        if (array_diff(array_keys($data), ['search', 'perPage', 'isSystem', 'guard', 'sort', 'direction', 'includeAssignments']) !== []) {
            throw new InvalidArgumentException('Unknown or protected Auth input fields.');
        }
        if (! array_key_exists('search', $data)) {
            $data['search'] = null;
        }
        if (! ($data['search'] === null || is_string($data['search']))) {
            throw new InvalidArgumentException('Invalid Auth input [search].');
        }
        if (! array_key_exists('perPage', $data)) {
            $data['perPage'] = null;
        }
        if (! ($data['perPage'] === null || is_int($data['perPage']))) {
            throw new InvalidArgumentException('Invalid Auth input [perPage].');
        }
        if (! array_key_exists('isSystem', $data)) {
            $data['isSystem'] = null;
        }
        if (! ($data['isSystem'] === null || is_bool($data['isSystem']))) {
            throw new InvalidArgumentException('Invalid Auth input [isSystem].');
        }
        if (! array_key_exists('guard', $data)) {
            $data['guard'] = null;
        }
        if (! ($data['guard'] === null || is_string($data['guard']))) {
            throw new InvalidArgumentException('Invalid Auth input [guard].');
        }
        if (! array_key_exists('sort', $data)) {
            $data['sort'] = null;
        }
        if (! ($data['sort'] === null || is_string($data['sort']))) {
            throw new InvalidArgumentException('Invalid Auth input [sort].');
        }
        if (! array_key_exists('direction', $data)) {
            $data['direction'] = null;
        }
        if (! ($data['direction'] === null || is_string($data['direction']))) {
            throw new InvalidArgumentException('Invalid Auth input [direction].');
        }
        if (! array_key_exists('includeAssignments', $data)) {
            $data['includeAssignments'] = false;
        }
        if (! is_bool($data['includeAssignments'] ?? null)) {
            throw new InvalidArgumentException('Invalid Auth input [includeAssignments].');
        }
        Validator::make($data, ['search' => ['nullable', 'sometimes', 'string', 'max:160'], 'perPage' => ['nullable', 'sometimes', 'integer'], 'isSystem' => ['nullable', 'sometimes', 'boolean'], 'guard' => ['nullable', 'sometimes', 'string', 'max:120'], 'sort' => ['nullable', 'sometimes', 'string', 'in:name,label,priority,created_at'], 'direction' => ['nullable', 'sometimes', 'string', 'in:asc,desc'], 'includeAssignments' => ['sometimes', 'boolean']])->validate();
        if ($data['sort'] !== null && ! in_array($data['sort'], ['name', 'label', 'priority', 'created_at'], true)) {
            throw new InvalidArgumentException('The role catalog sort is not supported.');
        }
        if ($data['direction'] !== null && ! in_array($data['direction'], ['asc', 'desc'], true)) {
            throw new InvalidArgumentException('The role catalog direction is not supported.');
        }

        return $data;
    }
}
