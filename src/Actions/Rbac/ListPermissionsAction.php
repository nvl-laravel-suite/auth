<?php

declare(strict_types=1);

namespace Nvl\Auth\Actions\Rbac;

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Contracts\Pagination\LengthAwarePaginator;
use Nvl\Auth\Enums\AuthFeature;
use Nvl\Auth\Enums\FeatureOperation;
use Nvl\Auth\Models\Permission;
use Nvl\Auth\Services\AuthModelRegistry;
use Nvl\Auth\Services\FeatureGate;
use Nvl\Auth\Services\ManagementAuthorizer;

/** Lists package permissions and assignment counts. */
final readonly class ListPermissionsAction
{
    /** Create the permission listing use case. */
    public function __construct(
        private FeatureGate $features,
        private ManagementAuthorizer $authorization,
        private AuthModelRegistry $models,
    ) {}

    /** @return LengthAwarePaginator<int, Permission> */
    public function execute(Authenticatable $actor, ?string $search = null, ?string $group = null, int $perPage = 25): LengthAwarePaginator
    {
        $this->features->assertAllowed(AuthFeature::Rbac, FeatureOperation::Read);
        $this->authorization->authorize($actor, 'nvl-auth.rbac.view');
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

        return $query->orderBy('group')->orderBy('name')->paginate(max(1, min($perPage, 100)));
    }
}
