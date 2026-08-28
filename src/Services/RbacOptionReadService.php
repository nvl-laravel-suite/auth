<?php

declare(strict_types=1);

namespace Nvl\Auth\Services;

use Illuminate\Database\Eloquent\Builder;
use Illuminate\Support\Collection;
use Nvl\Auth\Data\Display\PermissionOptionData;
use Nvl\Auth\Data\Display\RoleOptionData;
use Nvl\Auth\Models\Permission;
use Nvl\Auth\Models\Role;

/**
 * Executes projection-only RBAC option queries after an Action admits the read.
 *
 * @internal
 */
final readonly class RbacOptionReadService
{
    /** Create the internal option reader. */
    public function __construct(
        private AuthModelRegistry $models,
        private RbacPermissionGroupExpressions $groupExpressions,
    ) {}

    /**
     * Read a bounded role option collection.
     *
     * @return Collection<int, RoleOptionData>
     */
    public function roles(?string $search, int $limit): Collection
    {
        $class = $this->models->roleClass();
        $query = $class::query()->select([
            'id',
            'name',
            'display_name',
            'description',
            'is_system',
        ]);

        if ($search !== null) {
            $term = "%{$search}%";
            $query->where(static function ($searchQuery) use ($term): void {
                $searchQuery
                    ->where('name', 'like', $term)
                    ->orWhere('display_name', 'like', $term)
                    ->orWhere('description', 'like', $term);
            });
        }

        return $query
            ->orderByDesc('is_system')
            ->orderBy('name')
            ->orderBy('id')
            ->limit($limit)
            ->get()
            ->map(static fn (Role $role): RoleOptionData => RoleOptionData::fromModel($role));
    }

    /**
     * Read a bounded permission option collection.
     *
     * @return Collection<int, PermissionOptionData>
     */
    public function permissions(?string $search, ?string $group, int $limit): Collection
    {
        $class = $this->models->permissionClass();
        $query = $class::query()->select([
            'id',
            'name',
            'display_name',
            'description',
            'group',
        ]);

        if ($search !== null) {
            $term = "%{$search}%";
            $query->where(static function ($searchQuery) use ($term): void {
                $searchQuery
                    ->where('name', 'like', $term)
                    ->orWhere('display_name', 'like', $term)
                    ->orWhere('description', 'like', $term)
                    ->orWhere('group', 'like', $term);
            });
        }

        if ($group !== null) {
            $this->applyGroupFilter($query, $group);
        }

        return $query
            ->orderBy($this->groupExpressions->normalized($query))
            ->orderBy('name')
            ->orderBy('id')
            ->limit($limit)
            ->get()
            ->map(static fn (Permission $permission): PermissionOptionData => PermissionOptionData::fromModel($permission));
    }

    /**
     * Apply an exact filter using the same general-group normalization as DTOs.
     *
     * @param  Builder<Permission>  $query
     */
    private function applyGroupFilter(Builder $query, string $group): void
    {
        $query->where($this->groupExpressions->normalized($query), $group);
    }
}
