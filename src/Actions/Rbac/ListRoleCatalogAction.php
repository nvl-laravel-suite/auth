<?php

declare(strict_types=1);

namespace Nvl\Auth\Actions\Rbac;

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Contracts\Pagination\LengthAwarePaginator;
use Illuminate\Database\Eloquent\Builder;
use Nvl\Auth\Data\Display\RoleListItemData;
use Nvl\Auth\Data\Queries\RoleIndexQueryData;
use Nvl\Auth\Enums\AuthFeature;
use Nvl\Auth\Enums\FeatureOperation;
use Nvl\Auth\Exceptions\AuthException;
use Nvl\Auth\Models\Role;
use Nvl\Auth\Services\AuthModelRegistry;
use Nvl\Auth\Services\FeatureGate;
use Nvl\Auth\Services\ManagementAuthorizer;

/** Lists a safe, stable role catalog for non-HTTP consumers. */
final readonly class ListRoleCatalogAction
{
    /** Create the role catalog use case. */
    public function __construct(
        private FeatureGate $features,
        private ManagementAuthorizer $authorization,
        private AuthModelRegistry $models,
    ) {}

    /**
     * Return a bounded paginator whose items are package DTOs, never models.
     *
     * @return LengthAwarePaginator<int, RoleListItemData>
     */
    public function execute(
        Authenticatable $actor,
        RoleIndexQueryData $data,
    ): LengthAwarePaginator {
        $this->features->assertAllowed(AuthFeature::Rbac, FeatureOperation::Read);
        $this->authorization->authorize($actor, 'nvl-auth.rbac.view');
        $this->assertMaximumLength($data->search, 160, 'Role search');
        $this->assertMaximumLength($data->guard, 120, 'Role guard');
        $class = $this->models->roleClass();
        $query = $class::query()
            ->select([
                'id',
                'name',
                'display_name',
                'description',
                'guard_name',
                'is_system',
                'priority',
                'parent_id',
                'created_at',
            ])
            ->with('parent:id,name')
            ->withCount(['permissions', 'users']);

        if ($data->includeAssignments) {
            $query->with('permissions:id');
        }

        $search = trim((string) $data->search);

        if ($search !== '') {
            $term = "%{$search}%";
            $query->where(static function ($searchQuery) use ($term): void {
                $searchQuery
                    ->where('name', 'like', $term)
                    ->orWhere('display_name', 'like', $term)
                    ->orWhere('description', 'like', $term);
            });
        }

        if ($data->isSystem !== null) {
            $query->where('is_system', $data->isSystem);
        }

        $guard = trim((string) $data->guard);

        if ($guard !== '') {
            $query->where('guard_name', $guard);
        }

        $this->applyOrdering($query, $data);
        $paginator = $query->paginate(max(1, min($data->perPage ?? 25, 100)));

        return $paginator->through(
            static fn (Role $role): RoleListItemData => RoleListItemData::fromModel($role),
        );
    }

    /**
     * Apply an allowlisted, database-portable role ordering.
     *
     * @param  Builder<Role>  $query
     */
    private function applyOrdering(Builder $query, RoleIndexQueryData $data): void
    {
        $direction = $data->direction === 'desc' ? 'desc' : 'asc';

        if ($data->sort === null) {
            $query->orderByDesc('priority')->orderBy('name')->orderBy('id');

            return;
        }

        if ($data->sort === 'label') {
            $query->orderByRaw($direction === 'desc'
                ? "COALESCE(NULLIF(TRIM(display_name), ''), name) DESC"
                : "COALESCE(NULLIF(TRIM(display_name), ''), name) ASC");
        } else {
            $query->orderBy($data->sort, $direction);
        }

        $query->orderBy('id');
    }

    /** Reject oversized direct PHP input before it reaches a query. */
    private function assertMaximumLength(?string $value, int $maximum, string $label): void
    {
        if ($value !== null && mb_strlen(trim($value)) > $maximum) {
            throw new AuthException(
                'invalid_role_catalog_query',
                "{$label} may not exceed {$maximum} characters.",
            );
        }
    }
}
