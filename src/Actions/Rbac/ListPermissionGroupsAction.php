<?php

declare(strict_types=1);

namespace Nvl\Auth\Actions\Rbac;

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Support\Collection;
use Illuminate\Support\Str;
use LogicException;
use Nvl\Auth\Data\Display\PermissionGroupData;
use Nvl\Auth\Data\Display\PermissionOptionData;
use Nvl\Auth\Enums\AuthFeature;
use Nvl\Auth\Enums\FeatureOperation;
use Nvl\Auth\Services\AuthModelRegistry;
use Nvl\Auth\Services\FeatureGate;
use Nvl\Auth\Services\ManagementAuthorizer;

/** Lists normalized permission groups and their catalog counts. */
final readonly class ListPermissionGroupsAction
{
    /** Create the permission group listing use case. */
    public function __construct(
        private FeatureGate $features,
        private ManagementAuthorizer $authorization,
        private AuthModelRegistry $models,
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
        $rows = $class::query()
            ->select('group')
            ->selectRaw('COUNT(*) AS permissions_count')
            ->groupBy('group')
            ->get();
        $counts = [];

        foreach ($rows as $row) {
            $rawGroup = $row->getAttribute('group');
            $rawCount = $row->getAttribute('permissions_count');

            if ((! is_string($rawGroup) && $rawGroup !== null) || ! is_numeric($rawCount)) {
                throw new LogicException('Permission group aggregates returned an invalid database value.');
            }

            $group = PermissionOptionData::normalizeGroup($rawGroup);
            $counts[$group] = ($counts[$group] ?? 0) + (int) $rawCount;
        }

        ksort($counts);

        return collect($counts)->map(
            static fn (int $count, string $group): PermissionGroupData => new PermissionGroupData(
                value: $group,
                label: Str::headline($group),
                permissionsCount: $count,
            ),
        )->values();
    }
}
