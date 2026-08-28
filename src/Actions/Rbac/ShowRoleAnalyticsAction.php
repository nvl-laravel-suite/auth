<?php

declare(strict_types=1);

namespace Nvl\Auth\Actions\Rbac;

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Database\Eloquent\Builder;
use Illuminate\Database\Query\Builder as QueryBuilder;
use Nvl\Auth\Contracts\PrincipalAttributeMapper;
use Nvl\Auth\Data\Display\RoleAnalyticsData;
use Nvl\Auth\Enums\AuthFeature;
use Nvl\Auth\Enums\FeatureOperation;
use Nvl\Auth\Enums\PrincipalAttribute;
use Nvl\Auth\Models\Role;
use Nvl\Auth\Services\AuthModelRegistry;
use Nvl\Auth\Services\FeatureGate;
use Nvl\Auth\Services\ManagementAuthorizer;
use Nvl\Auth\Services\RbacEntityLocator;
use Nvl\Auth\Services\RbacPermissionGroupExpressions;
use stdClass;

/** Returns identity-free, constant-query analytics for one role. */
final readonly class ShowRoleAnalyticsAction
{
    /** Create the per-role analytics use case. */
    public function __construct(
        private FeatureGate $features,
        private ManagementAuthorizer $authorization,
        private RbacEntityLocator $entities,
        private AuthModelRegistry $models,
        private PrincipalAttributeMapper $principalAttributes,
        private RbacPermissionGroupExpressions $groupExpressions,
    ) {}

    /** Calculate current aggregates without loading related identities. */
    public function execute(Authenticatable $actor, Role|string $role): RoleAnalyticsData
    {
        $this->features->assertAllowed(AuthFeature::Rbac, FeatureOperation::Read);
        $this->authorization->authorize($actor, 'nvl-auth.rbac.view');
        $role = $this->entities->roleForConfiguredGuard($role);
        [$users, $activeUsers] = $this->userCounts($role);
        [$permissions, $permissionGroups] = $this->permissionCounts($role);
        $hierarchy = $this->hierarchy($role);

        return new RoleAnalyticsData(
            roleId: $role->id,
            users: $users,
            activeUsers: $activeUsers,
            inactiveUsers: max(0, $users - $activeUsers),
            permissions: $permissions,
            children: $hierarchy['children'],
            descendants: $hierarchy['descendants'],
            parentName: $hierarchy['parentName'],
            permissionGroups: $permissionGroups,
        );
    }

    /**
     * Count all and active assigned principals in one aggregate query.
     *
     * @return array{int, int}
     */
    private function userCounts(Role $role): array
    {
        $class = $this->models->rbacPrincipalClass();
        $query = $class::query()->whereHas('roles', static function (Builder $roles) use ($role): void {
            $roles->whereKey($role->id);
        });
        $activeColumn = $query->getModel()->qualifyColumn(
            $this->principalAttributes->column(PrincipalAttribute::Active),
        );
        $allUsers = (clone $query)->selectRaw('COUNT(*)');
        $activeUsers = (clone $query)
            ->where($activeColumn, true)
            ->selectRaw('COUNT(*)');
        $row = (new QueryBuilder($query->getQuery()->getConnection()))
            ->selectSub($allUsers->toBase(), 'aggregate_users')
            ->selectSub($activeUsers->toBase(), 'aggregate_active_users')
            ->first();

        if (! $row instanceof stdClass) {
            return [0, 0];
        }

        return [
            $this->integer($row->aggregate_users ?? null),
            $this->integer($row->aggregate_active_users ?? null),
        ];
    }

    /**
     * Count direct permissions and their canonical groups in one query.
     *
     * @return array{int, array<string, int>}
     */
    private function permissionCounts(Role $role): array
    {
        $class = $this->models->permissionClass();
        $query = $class::query()->whereHas('roles', static function (Builder $roles) use ($role): void {
            $roles->whereKey($role->id);
        });
        $rows = $query
            ->select([$this->groupExpressions->selected($query)])
            ->selectRaw('COUNT(*) AS permissions_count')
            ->groupBy($this->groupExpressions->normalized($query))
            ->toBase()
            ->get();
        $groups = [];

        foreach ($rows as $row) {
            if (! is_string($row->normalized_group ?? null)) {
                continue;
            }

            $groups[$row->normalized_group] = $this->integer($row->permissions_count ?? null);
        }

        return [array_sum($groups), $groups];
    }

    /**
     * Read the configured-guard graph once and traverse it with a visited set.
     *
     * @return array{children: int, descendants: int, parentName: string|null}
     */
    private function hierarchy(Role $role): array
    {
        $class = $this->models->roleClass();
        $roles = $class::query()
            ->select(['id', 'parent_id', 'name'])
            ->where('guard_name', $role->guard_name)
            ->get();
        $nodes = [];
        $childrenByParent = [];

        foreach ($roles as $candidate) {
            $nodes[$candidate->id] = [
                'name' => $candidate->name,
                'parentId' => $candidate->parent_id,
            ];

            if ($candidate->parent_id !== null) {
                $childrenByParent[$candidate->parent_id][] = $candidate->id;
            }
        }

        $directChildren = array_values(array_unique(array_filter(
            $childrenByParent[$role->id] ?? [],
            static fn (string $identifier): bool => $identifier !== $role->id,
        )));
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
        $parentName = is_string($parentId) && isset($nodes[$parentId])
            ? $nodes[$parentId]['name']
            : null;

        return [
            'children' => count($directChildren),
            'descendants' => $descendants,
            'parentName' => $parentName,
        ];
    }

    /** Normalize a database aggregate scalar without coercing objects or arrays. */
    private function integer(mixed $value): int
    {
        return is_numeric($value) ? (int) $value : 0;
    }
}
