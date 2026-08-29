<?php

declare(strict_types=1);

namespace Nvl\Auth\Actions\Rbac;

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Contracts\Pagination\LengthAwarePaginator;
use Nvl\Auth\Data\Display\RoleListItemData;
use Nvl\Auth\Enums\AuthFeature;
use Nvl\Auth\Enums\FeatureOperation;
use Nvl\Auth\Models\Role;
use Nvl\Auth\Services\AuthModelRegistry;
use Nvl\Auth\Services\FeatureGate;
use Nvl\Auth\Services\ManagementAuthorizer;

/** Lists package roles with their hierarchy and assignment summaries. */
final readonly class ListRolesAction
{
    /** Create the role listing use case. */
    public function __construct(
        private FeatureGate $features,
        private ManagementAuthorizer $authorization,
        private AuthModelRegistry $models,
    ) {}

    /** @return LengthAwarePaginator<int, RoleListItemData> */
    public function execute(Authenticatable $actor, ?string $search = null, int $perPage = 25): LengthAwarePaginator
    {
        $this->features->assertAllowed(AuthFeature::Rbac, FeatureOperation::Read);
        $this->authorization->authorize($actor, 'nvl-auth.rbac.view');
        $class = $this->models->roleClass();
        $query = $class::query()->with('parent')->withCount(['users', 'permissions']);

        if ($search !== null && trim($search) !== '') {
            $term = '%'.trim($search).'%';
            $query->where(static function ($searchQuery) use ($term): void {
                $searchQuery->where('name', 'like', $term)->orWhere('display_name', 'like', $term);
            });
        }

        $roles = $query
            ->orderByDesc('priority')
            ->orderBy('name')
            ->paginate(max(1, min($perPage, 100)));

        return $roles->through(
            static fn (Role $role): RoleListItemData => RoleListItemData::fromModel($role),
        );
    }
}
