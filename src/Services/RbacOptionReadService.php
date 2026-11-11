<?php

declare(strict_types=1);

namespace Nvl\Auth\Services;

use Illuminate\Database\Eloquent\Builder;
use Illuminate\Support\Collection;
use Nvl\Auth\Models\Permission;
use Nvl\Auth\Models\Role;
use Nvl\Auth\Support\LiteralSearch;

/**
 * Executes projection-only RBAC option queries after an Action admits the read.
 *
 * @internal
 */
final readonly class RbacOptionReadService
{
    /** Create the internal option reader. */
    public function __construct(private AuthModelRegistry $models, private RbacPermissionGroupExpressions $groupExpressions) {}

    /**
     * Read a bounded role option collection.
     *
     * @return Collection<int, Role>
     */
    public function roles(?string $search, int $limit): Collection
    {
        $class = $this->models->roleClass();
        $query = $class::query()->select(['id', 'name', 'display_name', 'description', 'is_system']);
        if ($search !== null) {
            LiteralSearch::contains($query, ['name', 'display_name', 'description'], $search);
        }

        return $query->orderByDesc('is_system')->orderBy('name')->orderBy('id')->limit($limit)->get();
    }

    /**
     * Read a bounded permission option collection.
     *
     * @return Collection<int, Permission>
     */
    public function permissions(?string $search, ?string $group, int $limit): Collection
    {
        $class = $this->models->permissionClass();
        $query = $class::query()->select(['id', 'name', 'display_name', 'description', 'group']);
        if ($search !== null) {
            LiteralSearch::contains($query, ['name', 'display_name', 'description', 'group'], $search);
        }
        if ($group !== null) {
            $this->applyGroupFilter($query, $group);
        }

        return $query->orderBy($this->groupExpressions->normalized($query))->orderBy('name')->orderBy('id')->limit($limit)->get();
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
