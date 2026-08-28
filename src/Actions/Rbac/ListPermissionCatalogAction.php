<?php

declare(strict_types=1);

namespace Nvl\Auth\Actions\Rbac;

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Contracts\Pagination\LengthAwarePaginator;
use Illuminate\Database\Eloquent\Builder;
use Nvl\Auth\Data\Display\PermissionListItemData;
use Nvl\Auth\Data\Queries\PermissionIndexQueryData;
use Nvl\Auth\Enums\AuthFeature;
use Nvl\Auth\Enums\FeatureOperation;
use Nvl\Auth\Exceptions\AuthException;
use Nvl\Auth\Models\Permission;
use Nvl\Auth\Services\AuthModelRegistry;
use Nvl\Auth\Services\FeatureGate;
use Nvl\Auth\Services\ManagementAuthorizer;

/** Lists a safe, stable permission catalog for non-HTTP consumers. */
final readonly class ListPermissionCatalogAction
{
    /** Create the permission catalog use case. */
    public function __construct(
        private FeatureGate $features,
        private ManagementAuthorizer $authorization,
        private AuthModelRegistry $models,
    ) {}

    /**
     * Return a bounded paginator whose items are package DTOs, never models.
     *
     * @return LengthAwarePaginator<int, PermissionListItemData>
     */
    public function execute(
        Authenticatable $actor,
        PermissionIndexQueryData $data,
    ): LengthAwarePaginator {
        $this->features->assertAllowed(AuthFeature::Rbac, FeatureOperation::Read);
        $this->authorization->authorize($actor, 'nvl-auth.rbac.view');
        $this->assertMaximumLength($data->search, 160, 'Permission search');
        $this->assertMaximumLength($data->group, 120, 'Permission group');
        $this->assertMaximumLength($data->guard, 120, 'Permission guard');
        $class = $this->models->permissionClass();
        $query = $class::query()
            ->select([
                'id',
                'name',
                'display_name',
                'description',
                'guard_name',
                'group',
                'created_at',
            ])
            ->withCount(['roles', 'users']);

        if ($data->includeAssignments) {
            $query->with('roles:id');
        }

        $search = trim((string) $data->search);

        if ($search !== '') {
            $term = "%{$search}%";
            $query->where(static function ($searchQuery) use ($term): void {
                $searchQuery
                    ->where('name', 'like', $term)
                    ->orWhere('display_name', 'like', $term)
                    ->orWhere('description', 'like', $term)
                    ->orWhere('group', 'like', $term);
            });
        }

        $group = trim((string) $data->group);

        if ($group !== '') {
            $this->applyGroupFilter($query, $group);
        }

        $guard = trim((string) $data->guard);

        if ($guard !== '') {
            $query->where('guard_name', $guard);
        }

        $this->applyOrdering($query, $data);
        $paginator = $query->paginate(max(1, min($data->perPage ?? 25, 100)));

        return $paginator->through(
            static fn (Permission $permission): PermissionListItemData => PermissionListItemData::fromModel($permission),
        );
    }

    /**
     * Apply an exact filter using the same general-group normalization as DTOs.
     *
     * @param  Builder<Permission>  $query
     */
    private function applyGroupFilter(Builder $query, string $group): void
    {
        if ($group !== 'general') {
            $query->where('group', $group);

            return;
        }

        $query->where(static function ($groupQuery): void {
            $groupQuery
                ->where('group', 'general')
                ->orWhereNull('group')
                ->orWhere('group', '');
        });
    }

    /**
     * Apply an allowlisted, database-portable permission ordering.
     *
     * @param  Builder<Permission>  $query
     */
    private function applyOrdering(Builder $query, PermissionIndexQueryData $data): void
    {
        $direction = $data->direction === 'desc' ? 'desc' : 'asc';

        if ($data->sort === null || $data->sort === 'group') {
            $query->orderBy('group', $direction);
        } elseif ($data->sort === 'label') {
            $query->orderByRaw($direction === 'desc'
                ? "COALESCE(NULLIF(TRIM(display_name), ''), name) DESC"
                : "COALESCE(NULLIF(TRIM(display_name), ''), name) ASC");
        } else {
            $query->orderBy($data->sort, $direction);
        }

        if ($data->sort === null) {
            $query->orderBy('name');
        }

        $query->orderBy('id');
    }

    /** Reject oversized direct PHP input before it reaches a query. */
    private function assertMaximumLength(?string $value, int $maximum, string $label): void
    {
        if ($value !== null && mb_strlen(trim($value)) > $maximum) {
            throw new AuthException(
                'invalid_permission_catalog_query',
                "{$label} may not exceed {$maximum} characters.",
            );
        }
    }
}
