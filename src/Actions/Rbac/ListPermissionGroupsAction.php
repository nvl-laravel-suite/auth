<?php

declare(strict_types=1);

namespace Nvl\Auth\Actions\Rbac;

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Support\Collection;
use Illuminate\Support\Str;
use LogicException;
use Nvl\Auth\Data\Display\PermissionGroupData;
use Nvl\Auth\Enums\AuthFeature;
use Nvl\Auth\Enums\FeatureOperation;
use Nvl\Auth\Services\AuthModelRegistry;
use Nvl\Auth\Services\FeatureGate;
use Nvl\Auth\Services\ManagementAuthorizer;
use Nvl\Auth\Services\RbacConsumerLimits;
use Nvl\Auth\Services\RbacPermissionGroupExpressions;

/** Lists normalized permission groups and their catalog counts. */
final readonly class ListPermissionGroupsAction
{
    /** Create the permission group listing use case. */
    public function __construct(
        private FeatureGate $features,
        private ManagementAuthorizer $authorization,
        private AuthModelRegistry $models,
        private RbacConsumerLimits $limits,
        private RbacPermissionGroupExpressions $groupExpressions,
    ) {}

    /**
     * Aggregate raw database groups in one query and normalize them in memory.
     *
     * @return Collection<int, PermissionGroupData>
     */
    public function execute(Authenticatable $actor): Collection
    {
        $this->features->assertAllowed(AuthFeature::Rbac, FeatureOperation::Read);
        $this->authorization->authorize($actor, 'nvl-auth.rbac.view');
        $class = $this->models->permissionClass();
        $query = $class::query();
        $rows = $query
            ->select($this->groupExpressions->selected($query))
            ->selectRaw('COUNT(*) AS permissions_count')
            ->groupBy('normalized_group')
            ->orderBy('normalized_group')
            ->limit($this->limits->permissionGroupLimit())
            ->get();

        return $rows->map(static function ($row): PermissionGroupData {
            $group = $row->getAttribute('normalized_group');
            $count = $row->getAttribute('permissions_count');

            if (! is_string($group) || ! is_numeric($count)) {
                throw new LogicException('Permission group aggregates returned an invalid database value.');
            }

            return new PermissionGroupData(
                value: $group,
                label: Str::headline($group),
                permissionsCount: (int) $count,
            );
        })->values();
    }
}
